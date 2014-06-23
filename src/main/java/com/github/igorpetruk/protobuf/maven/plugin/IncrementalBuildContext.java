package com.github.igorpetruk.protobuf.maven.plugin;

import com.google.common.collect.Lists;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.sonatype.plexus.build.incremental.DefaultBuildContext;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Properties;

/**
 * Implements a build context that hashes source files to detect changes for incremental building.
 * This is intended to replace the default implementation, which forces compilation.
 *
 * @author matt@osbolab.com (Matt Barnard)
 */
final class IncrementalBuildContext extends DefaultBuildContext {

  private static final Log log = new SystemStreamLog();

  private static final String INFO_COMMENT =
      "Protocol buffer source file\nIncremental build metadata";
  private static final String INFO_PATH_KEY = "file_abs_path";
  private static final String INFO_SIZE_KEY = "file_size";
  private static final String INFO_HASH_KEY = "file_hash";

  private static final String HASH_ALGORITHM = "MD5";
  private final MessageDigest refreshDigest = DigestUtils.getDigest(HASH_ALGORITHM);

  private static final String OUTPUT_NUMFILES_KEY = "num_output_files";
  private static final String OUTPUT_COMMENT =
      "Protocol buffer output files\nIncremental build metadata";

  private static final String INFO_HASH_ALGO_KEY = "hash_algorithm";


  private final File outputDirectory;
  private final File outputInfoFile;
  private final Path metadataPath;
  private Path basePath;


  IncrementalBuildContext(File outputDirectory, Path metadataPath) {
    this.outputDirectory = outputDirectory;
    this.metadataPath = metadataPath;
    String outputInfoFileName = DigestUtils.md5Hex(outputDirectory.getAbsolutePath());
    outputInfoFile = metadataPath.resolve(outputInfoFileName).toFile();
  }

  @Override
  public boolean isIncremental() {
    return true;
  }

  @Override
  public boolean hasDelta(String relpath) {
    if (basePath != null) {
      Path path = basePath.resolve(relpath);
      return hasDelta(path.toFile());
    }
    return false;
  }

  @Override
  public boolean hasDelta(List relpaths) {
    if (basePath != null) {
      for (Object relpath : relpaths) {
        if (relpath instanceof String) {
          Path path = basePath.resolve((String) relpath);
          if (hasDelta(path.toFile())) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @Override
  public void refresh(File file) {
    if (!file.exists() || !file.isFile()) {
      deleteInfo(file);
      return;
    }
    Properties info = new Properties();
    info.setProperty(INFO_PATH_KEY, file.getAbsolutePath());
    info.setProperty(INFO_SIZE_KEY, Long.toString(FileUtils.sizeOf(file)));
    info.setProperty(INFO_HASH_KEY, digestFile(file));
    info.setProperty(INFO_HASH_ALGO_KEY, refreshDigest.getAlgorithm());

    File infoFile = getInfoFile(file);
    try {
      if (!infoFile.createNewFile()) {
        if (!infoFile.delete() || !infoFile.createNewFile()) {
          throw new IOException(
              "Can't overwrite protobuf source file metadata: " + infoFile.getAbsolutePath());
        }
      }
    } catch (IOException createEx) {
      throw new RuntimeException(
          "Exception generating incremental build metadata for protobuf source.", createEx);
    }

    try (Writer output = new FileWriter(infoFile)) {
      info.store(output, INFO_COMMENT);
    } catch (IOException storeEx) {
      throw new RuntimeException(
          "Exception writing incremental build metadata for protobuf source file.", storeEx);
    }
  }

  @Override
  public boolean hasDelta(File file) {
    if (!file.exists() || !file.isFile() || !file.canRead()) {
      return true;
    }

    File infoFile = getInfoFile(file);
    if (!infoFile.exists() || !infoFile.isFile() || !infoFile.canRead()) {
      return true;
    }

    Properties info = new Properties();
    try (Reader input = new FileReader(infoFile)) {
      info.load(input);

    } catch (IOException e) {
      log.warn("Protobuf incremental build metadata is unreadable; forcing compilation of " +
               file.toString(), e);
      FileUtils.deleteQuietly(infoFile);
      return true;
    }

    return pathMismatch(info, file) || sizeMismatch(info, file) || hashMismatch(info, file);
  }

  void refreshOutputDir(File outputDir) {
    try {
      if (!outputInfoFile.createNewFile()) {
        if (!outputInfoFile.delete()) {
          throw new IOException("Can't delete metadata file.");
        } else {
          if (!outputInfoFile.createNewFile()) {
            throw new IOException("Can't create metadata file.");
          }
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Can't update output files metadata.", e);
    }
    List<File> files = Lists.newArrayList();
    int numFiles = countFilesAndPutInList(outputDir, files);
    log.info("Refreshing incremental build data for " + numFiles + " files.");

    Properties info = new Properties();
    info.setProperty(OUTPUT_NUMFILES_KEY, Integer.toString(numFiles));

    String outputDirName = outputDir.getName() + ":";

    for (File file : files) {
      String fileHash = digestFile(file);
      info.setProperty(outputDirName + file.getName(), fileHash.toLowerCase());
    }

    try (Writer output = new FileWriter(outputInfoFile)) {
      info.store(output, OUTPUT_COMMENT);
    } catch (IOException storeEx) {
      throw new RuntimeException(
          "Exception writing incremental build metadata for protobuf output files.", storeEx);
    }
  }

  boolean isOutputDirChanged() {
    if (!outputInfoFile.exists()) {
      return true;
    }
    if (!outputInfoFile.canRead()) {
      if (!outputInfoFile.delete()) {
        log.warn("Protobuf incremental build metadata is unreadable and can't be deleted.");
      }
      return true;
    }
    Properties info = new Properties();
    try (Reader input = new FileReader(outputInfoFile)) {
      info.load(input);

    } catch (IOException e) {
      log.warn("Protobuf incremental build metadata is unreadable; forcing compilation.", e);
      FileUtils.deleteQuietly(outputInfoFile);
      return true;
    }

    int numFiles = -1;
    try {
      numFiles = Integer.parseInt(info.getProperty(OUTPUT_NUMFILES_KEY));
    } catch (NumberFormatException e) {
      log.warn("Protobuf incremental build metadata is missing output file count.", e);
    }

    if (numFiles < 0) {
      return true;
    }

    List<File> files = Lists.newArrayList();
    if (numFiles != countFilesAndPutInList(outputDirectory, files)) {
      return true;
    }

    String hashUsed = info.getProperty(INFO_HASH_ALGO_KEY, "").trim().toLowerCase();

    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance(hashUsed);
    } catch (NoSuchAlgorithmException e) {
      log.warn("Protobuf incremental build metadata used hash algorithm I don't recognize.");
      return true;
    }

    String outputDirName = outputDirectory.getName() + ":";
    for (File file : files) {
      digest.reset();
      try (InputStream input = new FileInputStream(file)) {
        DigestUtils.updateDigest(digest, input);
      } catch (IOException e) {
        log.warn("Exception getting output directory hash. Compilation will be forced.", e);
        return true;
      }
      String fileHash = Hex.encodeHexString(digest.digest()).trim().toLowerCase();
      if (!fileHash.equals(info.getProperty(outputDirName + file.getName(), ""))) {
        return true;
      }
    }

    return false;
  }

  private int countFilesAndPutInList(File directory, List<File> addTo) {
    int filesFound = 0;
    if (directory.getAbsolutePath().startsWith(metadataPath.toString())) {
      return 0;
    }
    File[] files = directory.listFiles();
    if (files != null) {
      for (File file : files) {
        if (file.isDirectory()) {
          filesFound += countFilesAndPutInList(file, addTo);
        } else {
          ++filesFound;
          addTo.add(file);
        }
      }
    }
    return filesFound;
  }

  void setWorkingDirectory(Path path) {
    basePath = path;
  }

  private boolean pathMismatch(Properties info, File file) {
    String pastPath = info.getProperty(INFO_PATH_KEY, "");
    if (pastPath.isEmpty()) {
      log.warn("Protobuf incremental build metadata is missing path.");
    }

    return !pastPath.equals(file.getAbsolutePath());
  }

  private boolean sizeMismatch(Properties info, File file) {
    long pastSize = -1;
    try {
      pastSize = Long.parseLong(info.getProperty(INFO_SIZE_KEY));
    } catch (NumberFormatException | NullPointerException e) {
      log.warn("Protobuf incremental build metadata is missing file size.", e);
    }
    return !(FileUtils.sizeOf(file) == pastSize);
  }

  private boolean hashMismatch(Properties info, File file) {
    String pastHash = info.getProperty(INFO_HASH_KEY, "").trim().toLowerCase();
    String hashUsed = info.getProperty(INFO_HASH_ALGO_KEY, "").trim().toLowerCase();

    if (pastHash.isEmpty() || hashUsed.isEmpty()) {
      log.warn("Protobuf incremental build metadata is missing file hash.");
      return true;
    }
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance(hashUsed);
    } catch (NoSuchAlgorithmException e) {
      log.warn("Protobuf incremental build metadata used hash algorithm I don't recognize.");
      return true;
    }

    String fileHash;

    try (InputStream input = new FileInputStream(file)) {
      DigestUtils.updateDigest(digest, input);
      fileHash = Hex.encodeHexString(digest.digest()).trim().toLowerCase();

    } catch (IOException e) {
      log.warn("Exception hashing protobuf source file for incremental build delta.", e);
      return true;
    }

    return !fileHash.equals(pastHash);
  }

  private void deleteInfo(File file) {
    FileUtils.deleteQuietly(getInfoFile(file));
  }

  private File getInfoFile(File file) {
    String filePathHash = DigestUtils.md5Hex(file.getAbsolutePath());
    return metadataPath.resolve(filePathHash).toFile();
  }

  private String digestFile(File file) {
    refreshDigest.reset();
    try (InputStream fileStream = new FileInputStream(file)) {
      DigestUtils.updateDigest(refreshDigest, fileStream);
    } catch (IOException ignored) {
    }
    return Hex.encodeHexString(refreshDigest.digest());
  }
}
