// SPDX-License-Identifier: MIT OR Apache-2.0
// CTP Bundle parsing and extraction

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;
use flate2::read::GzDecoder;

/// CTP Bundle structure (per runtime-integration.adoc Section 5)
pub struct CtpBundle {
    pub manifest: Manifest,
    pub oci_layout_path: PathBuf,
    pub attestations_path: PathBuf,
    pub signatures_path: PathBuf,
    temp_dir: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub image_digest: String,
    #[serde(default)]
    pub metadata: ManifestMetadata,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ManifestMetadata {
    pub build_timestamp: Option<String>,
    pub builder: Option<String>,
}

impl CtpBundle {
    /// Load a .ctp bundle from the filesystem
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("Bundle not found: {:?}", path);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir()
            .context("Failed to create temp directory")?
            .into_path();

        // Extract tarball
        Self::extract_tarball(path, &temp_dir)?;

        // Parse manifest.toml
        let manifest_path = temp_dir.join("manifest.toml");
        let manifest_content = std::fs::read_to_string(&manifest_path)
            .context("Failed to read manifest.toml")?;

        let manifest: Manifest = toml::from_str(&manifest_content)
            .context("Failed to parse manifest.toml")?;

        Ok(Self {
            manifest,
            oci_layout_path: temp_dir.join("oci-layout"),
            attestations_path: temp_dir.join("attestations"),
            signatures_path: temp_dir.join("signatures"),
            temp_dir,
        })
    }

    /// Extract the tarball to a directory
    fn extract_tarball(tar_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(tar_path)
            .context("Failed to open .ctp file")?;

        // Try gzip decompression first, fallback to uncompressed
        let tar: Box<dyn Read> = if Self::is_gzipped(tar_path)? {
            Box::new(GzDecoder::new(file))
        } else {
            Box::new(file)
        };

        let mut archive = Archive::new(tar);
        archive.unpack(dest)
            .context("Failed to unpack .ctp tarball")?;

        Ok(())
    }

    /// Check if file is gzipped
    fn is_gzipped(path: &Path) -> Result<bool> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 2];
        file.read_exact(&mut magic)?;
        Ok(magic == [0x1f, 0x8b])  // gzip magic number
    }

    /// Extract OCI layout to a new temporary directory
    pub fn extract_oci_layout(&self) -> Result<PathBuf> {
        let oci_dest = tempfile::tempdir()
            .context("Failed to create OCI temp directory")?
            .into_path();

        Self::copy_dir_recursive(&self.oci_layout_path, &oci_dest)?;

        Ok(oci_dest)
    }

    /// Recursively copy directory
    fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let dst_path = dst.join(entry.file_name());

            if ty.is_dir() {
                Self::copy_dir_recursive(&entry.path(), &dst_path)?;
            } else {
                std::fs::copy(entry.path(), dst_path)?;
            }
        }

        Ok(())
    }

    /// Get attestation bundle path
    pub fn attestation_bundle_path(&self) -> PathBuf {
        self.attestations_path.join("bundle.json")
    }

    /// Get SBOM path
    pub fn sbom_path(&self) -> PathBuf {
        self.attestations_path.join("sbom.json")
    }

    /// Get provenance path
    pub fn provenance_path(&self) -> PathBuf {
        self.attestations_path.join("provenance.json")
    }
}

impl Drop for CtpBundle {
    fn drop(&mut self) {
        // Clean up temporary directory
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_parsing() {
        let toml_str = r#"
            name = "nginx"
            version = "1.26"
            image_digest = "sha256:abc123"
        "#;

        let manifest: Manifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.name, "nginx");
        assert_eq!(manifest.version, "1.26");
    }
}
