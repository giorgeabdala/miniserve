use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use libflate::gzip::Encoder;
use serde::Deserialize;
use strum::{Display, EnumIter, EnumString};
use tar::Builder;
use zip::{ZipWriter, write};

use crate::errors::RuntimeError;

/// Default buffer size for streaming operations (64KB)
const DEFAULT_BUFFER_SIZE: usize = 65536;

/// Maximum memory usage limit for ZIP generation (256MB)
const MAX_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

/// Available archive methods
#[derive(Deserialize, Clone, Copy, EnumIter, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArchiveMethod {
    /// Gzipped tarball
    TarGz,

    /// Regular tarball
    Tar,

    /// Regular zip
    Zip,
}

impl ArchiveMethod {
    pub fn extension(self) -> String {
        match self {
            Self::TarGz => "tar.gz",
            Self::Tar => "tar",
            Self::Zip => "zip",
        }
        .to_string()
    }

    pub fn content_type(self) -> String {
        match self {
            Self::TarGz => "application/gzip",
            Self::Tar => "application/tar",
            Self::Zip => "application/zip",
        }
        .to_string()
    }

    pub fn is_enabled(self, tar_enabled: bool, tar_gz_enabled: bool, zip_enabled: bool) -> bool {
        match self {
            Self::TarGz => tar_gz_enabled,
            Self::Tar => tar_enabled,
            Self::Zip => zip_enabled,
        }
    }

    /// Make an archive out of the given directory, and write the output to the given writer.
    ///
    /// Recursively includes all files and subdirectories.
    ///
    /// If `skip_symlinks` is `true`, symlinks fill not be followed and will just be ignored.
    pub fn create_archive<T, W>(
        self,
        dir: T,
        skip_symlinks: bool,
        out: W,
    ) -> Result<(), RuntimeError>
    where
        T: AsRef<Path>,
        W: std::io::Write,
    {
        let dir = dir.as_ref();
        match self {
            Self::TarGz => tar_gz(dir, skip_symlinks, out),
            Self::Tar => tar_dir(dir, skip_symlinks, out),
            Self::Zip => zip_dir_with_temp_file(dir, skip_symlinks, out),
        }
    }
}

/// Write a gzipped tarball of `dir` in `out`.
fn tar_gz<W>(dir: &Path, skip_symlinks: bool, out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let mut out = Encoder::new(out).map_err(|e| RuntimeError::IoError("GZIP".to_string(), e))?;

    tar_dir(dir, skip_symlinks, &mut out)?;

    out.finish()
        .into_result()
        .map_err(|e| RuntimeError::IoError("GZIP finish".to_string(), e))?;

    Ok(())
}

/// Write a tarball of `dir` in `out`.
///
/// The target directory will be saved as a top-level directory in the archive.
///
/// For example, consider this directory structure:
///
/// ```ignore
/// a
/// └── b
///     └── c
///         ├── e
///         ├── f
///         └── g
/// ```
///
/// Making a tarball out of `"a/b/c"` will result in this archive content:
///
/// ```ignore
/// c
/// ├── e
/// ├── f
/// └── g
/// ```
fn tar_dir<W>(dir: &Path, skip_symlinks: bool, out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let inner_folder = dir.file_name().ok_or_else(|| {
        RuntimeError::InvalidPathError("Directory name terminates in \"..\"".to_string())
    })?;

    let directory = inner_folder.to_str().ok_or_else(|| {
        RuntimeError::InvalidPathError(
            "Directory name contains invalid UTF-8 characters".to_string(),
        )
    })?;

    tar(dir, directory.to_string(), skip_symlinks, out)
        .map_err(|e| RuntimeError::ArchiveCreationError("tarball".to_string(), Box::new(e)))
}

/// Writes a tarball of `dir` in `out`.
///
/// The content of `src_dir` will be saved in the archive as a folder named `inner_folder`.
fn tar<W>(
    src_dir: &Path,
    inner_folder: String,
    skip_symlinks: bool,
    out: W,
) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let mut tar_builder = Builder::new(out);

    tar_builder.follow_symlinks(!skip_symlinks);

    // Recursively adds the content of src_dir into the archive stream
    tar_builder
        .append_dir_all(inner_folder, src_dir)
        .map_err(|e| {
            RuntimeError::IoError(
                format!(
                    "Failed to append the content of {} to the TAR archive",
                    src_dir.to_str().unwrap_or("file")
                ),
                e,
            )
        })?;

    // Finish the archive
    tar_builder.into_inner().map_err(|e| {
        RuntimeError::IoError("Failed to finish writing the TAR archive".to_string(), e)
    })?;

    Ok(())
}

/// Write a zip of `dir` in `out` using streaming I/O.
///
/// The target directory will be saved as a top-level directory in the archive.
/// This implementation uses chunked reading to prevent memory exhaustion.
///
/// For example, consider this directory structure:
///
/// ```ignore
/// a
/// └── b
///     └── c
///         ├── e
///         ├── f
///         └── g
/// ```
///
/// Making a zip out of `"a/b/c"` will result in this archive content:
///
/// ```ignore
/// c
/// ├── e
/// ├── f
/// └── g
/// ```
fn create_zip_from_directory_streaming<W>(
    out: W,
    directory: &Path,
    skip_symlinks: bool,
    buffer_size: usize,
    memory_limit: usize,
) -> Result<(), RuntimeError>
where
    W: std::io::Write + std::io::Seek,
{
    let options =
        write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut paths_queue: Vec<PathBuf> = vec![directory.to_path_buf()];
    let zip_root_folder_name = directory.file_name().ok_or_else(|| {
        RuntimeError::InvalidPathError("Directory name terminates in \"..\"".to_string())
    })?;

    let mut zip_writer = ZipWriter::new(out);
    let mut buffer = vec![0u8; buffer_size];
    let mut total_memory_used = 0usize;

    while !paths_queue.is_empty() {
        let next = paths_queue.pop().ok_or_else(|| {
            RuntimeError::ArchiveCreationDetailError("Could not get path from queue".to_string())
        })?;
        let current_dir = next.as_path();
        let directory_entry_iterator = std::fs::read_dir(current_dir)
            .map_err(|e| RuntimeError::IoError("Could not read directory".to_string(), e))?;
        let zip_directory = Path::new(zip_root_folder_name).join(
            current_dir.strip_prefix(directory).map_err(|_| {
                RuntimeError::ArchiveCreationDetailError(
                    "Could not append base directory".to_string(),
                )
            })?,
        );

        for entry in directory_entry_iterator {
            let entry_path = entry
                .map_err(|e| {
                    RuntimeError::IoError("Could not read directory entry".to_string(), e)
                })?
                .path();
            // Use symlink_metadata to detect symlinks without following them
            let entry_metadata = std::fs::symlink_metadata(&entry_path)
                .map_err(|e| RuntimeError::IoError("Could not get file metadata".to_string(), e))?;

            // Skip symlinks if requested
            if entry_metadata.file_type().is_symlink() && skip_symlinks {
                continue;
            }

            let current_entry_name = entry_path.file_name().ok_or_else(|| {
                RuntimeError::InvalidPathError("Invalid file or directory name".to_string())
            })?;

            if entry_metadata.is_file() {
                // Check memory usage limit before processing large files
                let file_size = entry_metadata.len() as usize;
                if total_memory_used + file_size > memory_limit {
                    return Err(RuntimeError::ArchiveCreationDetailError(format!(
                        "Memory limit exceeded: {total_memory_used} + {file_size} > {memory_limit}"
                    )));
                }

                let mut file = File::open(&entry_path)
                    .map_err(|e| RuntimeError::IoError("Could not open file".to_string(), e))?;

                let relative_path = zip_directory.join(current_entry_name).into_os_string();
                zip_writer
                    .start_file(relative_path.to_string_lossy(), options)
                    .map_err(|e| {
                        RuntimeError::ArchiveCreationDetailError(format!(
                            "Could not add file path to ZIP: {e}"
                        ))
                    })?;

                // Stream file content in chunks
                loop {
                    let bytes_read = file.read(&mut buffer).map_err(|e| {
                        RuntimeError::IoError("Could not read from file".to_string(), e)
                    })?;

                    if bytes_read == 0 {
                        break; // End of file
                    }

                    zip_writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                        RuntimeError::ArchiveCreationDetailError(format!(
                            "Could not write file chunk to ZIP: {e}"
                        ))
                    })?;
                }

                total_memory_used += buffer_size.min(file_size);
            } else if entry_metadata.is_dir() {
                let relative_path = zip_directory.join(current_entry_name).into_os_string();
                zip_writer
                    .add_directory(relative_path.to_string_lossy(), options)
                    .map_err(|e| {
                        RuntimeError::ArchiveCreationDetailError(format!(
                            "Could not add directory path to ZIP: {e}"
                        ))
                    })?;
                paths_queue.push(entry_path);
            }
        }
    }

    zip_writer.finish().map_err(|e| {
        RuntimeError::ArchiveCreationDetailError(format!(
            "Could not finish writing ZIP archive: {e}"
        ))
    })?;
    Ok(())
}

/// Configuration for ZIP streaming operations
#[derive(Debug, Clone)]
pub struct ZipStreamConfig {
    /// Buffer size for file reading (default: 64KB)
    pub buffer_size: usize,
    /// Memory usage limit (default: 256MB)
    pub memory_limit: usize,
}

impl Default for ZipStreamConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            memory_limit: MAX_MEMORY_LIMIT,
        }
    }
}

/// Writes a zip of `dir` directly to `out` using streaming I/O.
///
/// This function streams the ZIP content directly to the output writer,
/// preventing memory exhaustion on large directories.
fn zip_data_streaming<W>(
    src_dir: &Path,
    skip_symlinks: bool,
    out: W,
    config: ZipStreamConfig,
) -> Result<(), RuntimeError>
where
    W: std::io::Write + std::io::Seek,
{
    create_zip_from_directory_streaming(
        out,
        src_dir,
        skip_symlinks,
        config.buffer_size,
        config.memory_limit,
    )
    .map_err(|e| {
        RuntimeError::ArchiveCreationError(
            "Failed to create the streaming ZIP archive".to_string(),
            Box::new(e),
        )
    })
}

/// Creates a ZIP archive using a temporary file for non-seekable writers.
///
/// This function addresses the issue where ZIP archives require seekable writers
/// but the output stream (like network streams or pipes) may not support seeking.
/// It creates the ZIP in a temporary file and then streams it to the output.
fn zip_dir_with_temp_file<W>(
    dir: &Path,
    skip_symlinks: bool,
    mut out: W,
) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let inner_folder = dir.file_name().ok_or_else(|| {
        RuntimeError::InvalidPathError("Directory name terminates in \"..\"".to_string())
    })?;

    inner_folder.to_str().ok_or_else(|| {
        RuntimeError::InvalidPathError(
            "Directory name contains invalid UTF-8 characters".to_string(),
        )
    })?;

    // Create a temporary file for the ZIP archive
    let mut temp_file = NamedTempFile::new().map_err(|e| {
        RuntimeError::IoError("Failed to create temporary file for ZIP".to_string(), e)
    })?;

    // Create the ZIP archive in the temporary file using streaming
    let config = ZipStreamConfig::default();
    zip_data_streaming(dir, skip_symlinks, &mut temp_file, config)
        .map_err(|e| RuntimeError::ArchiveCreationError("zip".to_string(), Box::new(e)))?;

    // Rewind the temporary file to the beginning
    temp_file.seek(std::io::SeekFrom::Start(0)).map_err(|e| {
        RuntimeError::IoError(
            "Failed to seek to start of temporary ZIP file".to_string(),
            e,
        )
    })?;

    // Stream the ZIP content from temporary file to output using chunks
    let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE];
    loop {
        let bytes_read = temp_file.read(&mut buffer).map_err(|e| {
            RuntimeError::IoError("Failed to read from temporary ZIP file".to_string(), e)
        })?;

        if bytes_read == 0 {
            break; // End of file
        }

        out.write_all(&buffer[..bytes_read]).map_err(|e| {
            RuntimeError::IoError("Failed to write ZIP data to output".to_string(), e)
        })?;
    }

    out.flush()
        .map_err(|e| RuntimeError::IoError("Failed to flush ZIP output".to_string(), e))?;

    // Temporary file is automatically deleted when it goes out of scope
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::{Cursor, Write};
    use tempfile::TempDir;

    /// Helper function to create a test directory structure with various file sizes
    fn create_test_directory(temp_dir: &TempDir, large_file_size: usize) -> std::io::Result<()> {
        let root = temp_dir.path();

        // Create directory structure
        fs::create_dir(root.join("subdir1"))?;
        fs::create_dir(root.join("subdir2"))?;
        fs::create_dir_all(root.join("subdir1/nested"))?;

        // Create small files
        File::create(root.join("small.txt"))?.write_all(b"Hello, world!")?;
        File::create(root.join("subdir1/small2.txt"))?.write_all(b"Another small file")?;
        File::create(root.join("subdir1/nested/small3.txt"))?.write_all(b"Nested file")?;

        // Create medium file (1KB)
        let medium_content = "x".repeat(1024);
        File::create(root.join("medium.txt"))?.write_all(medium_content.as_bytes())?;

        // Create large file (configurable size)
        let large_content = "y".repeat(large_file_size);
        File::create(root.join("large.txt"))?.write_all(large_content.as_bytes())?;

        // Create empty file
        File::create(root.join("empty.txt"))?;

        Ok(())
    }

    #[test]
    fn test_streaming_zip_with_small_files() -> Result<(), RuntimeError> {
        // Create test directory
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;
        create_test_directory(&temp_dir, 1024)
            .map_err(|e| RuntimeError::IoError("Failed to setup test dir".to_string(), e))?;

        // Test streaming ZIP creation
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), false, &mut cursor)?;
        }

        // Verify ZIP was created and has content
        assert!(!output.is_empty(), "ZIP output should not be empty");
        assert!(output.len() > 100, "ZIP should contain compressed data");

        // Basic ZIP signature check (PK\x03\x04 or PK\x05\x06)
        assert!(
            output.starts_with(b"PK\x03\x04") || output.starts_with(b"PK\x05\x06"),
            "Output should be a valid ZIP file"
        );

        Ok(())
    }

    #[test]
    fn test_streaming_zip_memory_limit() -> Result<(), RuntimeError> {
        // Create test directory with large file
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;
        create_test_directory(&temp_dir, 512 * 1024)
            .map_err(|e| RuntimeError::IoError("Failed to setup test dir".to_string(), e))?;

        // Test with normal memory limit - should succeed
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), false, &mut cursor)?;
        }

        assert!(
            !output.is_empty(),
            "ZIP creation should succeed with normal memory limit"
        );

        Ok(())
    }

    #[test]
    fn test_streaming_zip_preserves_directory_structure() -> Result<(), RuntimeError> {
        use zip::ZipArchive;

        // Create test directory
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;
        create_test_directory(&temp_dir, 100)
            .map_err(|e| RuntimeError::IoError("Failed to setup test dir".to_string(), e))?;

        // Create ZIP
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), false, &mut cursor)?;
        }

        // Read ZIP and verify structure
        let cursor = Cursor::new(output);
        let archive = ZipArchive::new(cursor).map_err(|e| {
            RuntimeError::ArchiveCreationDetailError(format!("Failed to read ZIP: {e}"))
        })?;

        let mut file_names: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();
        file_names.sort();

        // Verify expected files are present (directory names vary by temp dir name)
        let has_small_txt = file_names.iter().any(|name| name.ends_with("small.txt"));
        let has_medium_txt = file_names.iter().any(|name| name.ends_with("medium.txt"));
        let has_nested_file = file_names
            .iter()
            .any(|name| name.contains("nested") && name.ends_with("small3.txt"));

        assert!(
            has_small_txt,
            "ZIP should contain small.txt: {:?}",
            file_names
        );
        assert!(
            has_medium_txt,
            "ZIP should contain medium.txt: {:?}",
            file_names
        );
        assert!(
            has_nested_file,
            "ZIP should contain nested file: {:?}",
            file_names
        );

        // Verify we have directories
        let has_directories = file_names.iter().any(|name| name.ends_with("/"));
        assert!(
            has_directories,
            "ZIP should contain directories: {:?}",
            file_names
        );

        Ok(())
    }

    #[test]
    fn test_streaming_zip_with_symlinks_skipped() -> Result<(), RuntimeError> {
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;
        let root = temp_dir.path();

        // Create a regular file
        File::create(root.join("regular.txt"))
            .and_then(|mut f| f.write_all(b"regular content"))
            .map_err(|e| RuntimeError::IoError("Failed to create test file".to_string(), e))?;

        // Create a symlink (only on Unix-like systems)
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("regular.txt"), root.join("symlink.txt"))
                .map_err(|e| RuntimeError::IoError("Failed to create symlink".to_string(), e))?;
        }

        // Test with symlinks skipped
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), true, &mut cursor)?;
        }

        assert!(
            !output.is_empty(),
            "ZIP should be created even with symlinks skipped"
        );

        // Verify ZIP contains regular file but not symlink
        #[cfg(unix)]
        {
            use zip::ZipArchive;
            let cursor = Cursor::new(output);
            let archive = ZipArchive::new(cursor).map_err(|e| {
                RuntimeError::ArchiveCreationDetailError(format!("Failed to read ZIP: {e}"))
            })?;
            let file_names: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();

            let has_regular = file_names.iter().any(|name| name.ends_with("regular.txt"));
            let has_symlink = file_names.iter().any(|name| name.ends_with("symlink.txt"));

            assert!(has_regular, "ZIP should contain regular file");
            assert!(!has_symlink, "ZIP should not contain symlink when skipped");
        }

        Ok(())
    }

    #[test]
    fn test_streaming_zip_error_handling() {
        use std::path::PathBuf;

        // Test with non-existent directory
        let non_existent = PathBuf::from("/non/existent/directory");
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            let result = ArchiveMethod::Zip.create_archive(&non_existent, false, &mut cursor);
            assert!(result.is_err(), "Should fail with non-existent directory");
        }
    }

    #[test]
    fn test_streaming_zip_empty_directory() -> Result<(), RuntimeError> {
        // Create empty directory
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;

        // Test ZIP creation with empty directory
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), false, &mut cursor)?;
        }

        assert!(
            !output.is_empty(),
            "ZIP should be created even for empty directory"
        );

        // Verify it's a valid ZIP
        assert!(
            output.starts_with(b"PK"),
            "Output should be a valid ZIP file"
        );

        Ok(())
    }

    #[test]
    fn test_streaming_zip_performance_benchmark() -> Result<(), RuntimeError> {
        use std::time::Instant;

        // Create test directory with multiple files
        let temp_dir = TempDir::new()
            .map_err(|e| RuntimeError::IoError("Failed to create temp dir".to_string(), e))?;
        create_test_directory(&temp_dir, 10240)
            .map_err(|e| RuntimeError::IoError("Failed to setup test dir".to_string(), e))?;

        // Add more files for better performance testing
        for i in 0..20 {
            File::create(temp_dir.path().join(format!("file_{}.txt", i)))
                .and_then(|mut f| f.write_all(format!("Content of file {}", i).as_bytes()))
                .map_err(|e| RuntimeError::IoError("Failed to create test file".to_string(), e))?;
        }

        // Measure time
        let start = Instant::now();
        let mut output = Vec::new();
        {
            let mut cursor = Cursor::new(&mut output);
            ArchiveMethod::Zip.create_archive(temp_dir.path(), false, &mut cursor)?;
        }
        let duration = start.elapsed();

        assert!(!output.is_empty(), "ZIP should be created");
        println!("Streaming ZIP creation took: {:?}", duration);

        // Performance assertion - should complete in reasonable time
        assert!(
            duration.as_secs() < 10,
            "ZIP creation should complete within 10 seconds"
        );

        Ok(())
    }

    #[test]
    fn test_zip_stream_config_default() {
        let config = ZipStreamConfig::default();
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(config.memory_limit, MAX_MEMORY_LIMIT);
    }

    #[test]
    fn test_zip_stream_config_custom() {
        let config = ZipStreamConfig {
            buffer_size: 32768,
            memory_limit: 128 * 1024 * 1024,
        };
        assert_eq!(config.buffer_size, 32768);
        assert_eq!(config.memory_limit, 128 * 1024 * 1024);
    }
}
