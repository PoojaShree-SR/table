import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class FileIntegrityMonitor {

    private Map<String, String> fileHashes = new HashMap<>();

    // Function to compute file hash using SHA-256
    public String computeFileHash(Path filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = Files.readAllBytes(filePath);
        byte[] hashBytes = digest.digest(fileBytes);
        StringBuilder hashString = new StringBuilder();
        for (byte b : hashBytes) {
            hashString.append(String.format("%02x", b));
        }
        return hashString.toString();
    }

    // Initialize hashes of all files in the directory
    public void initializeFileHashes(String directoryPath) throws IOException, NoSuchAlgorithmException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(directoryPath))) {
            for (Path entry : stream) {
                if (Files.isRegularFile(entry)) {
                    fileHashes.put(entry.toString(), computeFileHash(entry));
                }
            }
        }
        System.out.println("Initial file hashes stored.");
    }

    // Monitor files for changes
    public void monitorFiles(String directoryPath) throws IOException, NoSuchAlgorithmException, InterruptedException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Path path = Paths.get(directoryPath);
        path.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE, StandardWatchEventKinds.ENTRY_MODIFY);

        System.out.println("Monitoring directory: " + directoryPath);

        while (true) {
            WatchKey key = watchService.take();
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                Path changedFilePath = path.resolve((Path) event.context());

                if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
                    System.out.println("File created: " + changedFilePath);
                    fileHashes.put(changedFilePath.toString(), computeFileHash(changedFilePath));
                } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                    System.out.println("File deleted: " + changedFilePath);
                    fileHashes.remove(changedFilePath.toString());
                } else if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                    System.out.println("File modified: " + changedFilePath);
                    String newHash = computeFileHash(changedFilePath);
                    String oldHash = fileHashes.get(changedFilePath.toString());

                    if (oldHash != null && !newHash.equals(oldHash)) {
                        System.out.println("File integrity compromised: " + changedFilePath);
                    }

                    fileHashes.put(changedFilePath.toString(), newHash);
                }
            }
            boolean valid = key.reset();
            if (!valid) {
                break;
            }
        }
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        FileIntegrityMonitor monitor = new FileIntegrityMonitor();
        
        // Replace the directory path with the one you want to monitor
        String directoryPath = "C:\\path_to_monitor"; 
        monitor.initializeFileHashes(directoryPath);
        monitor.monitorFiles(directoryPath);
    }
}
