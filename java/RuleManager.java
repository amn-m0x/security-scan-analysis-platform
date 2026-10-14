import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

public class RuleManager {
    private static final Path ACTIVE = Path.of("rules", "rules.yaml");
    private static final Path VERSIONS = Path.of("rules", "versions");

    private static String sha256(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        return HexFormat.of().formatHex(digest);
    }

    private static void snapshot(String version) throws Exception {
        if (!version.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) {
            throw new IllegalArgumentException(
                "Use 1-64 letters, digits, hyphens or underscores."
            );
        }

        if (!Files.isRegularFile(ACTIVE)) {
            throw new IOException(
                "rules/rules.yaml not found. Run from the project root."
            );
        }

        byte[] original = Files.readAllBytes(ACTIVE);
        if (original.length == 0) {
            throw new IOException("The rules file is empty.");
        }

        Files.createDirectories(VERSIONS);
        Path destination = VERSIONS.resolve(version + ".yaml");

        // Copy without replacing an existing version.
        Files.copy(ACTIVE, destination);

        byte[] saved = Files.readAllBytes(destination);
        if (!MessageDigest.isEqual(original, saved)) {
            throw new IOException(
                "Verification failed. The rules may have changed during copying."
            );
        }

        System.out.println("Saved version: " + version);
        System.out.println("File: " + destination);
        System.out.println("SHA-256: " + sha256(saved));
        System.out.println("PASS: snapshot matches the original rules");
    }

    private static void listVersions() throws IOException {
        if (!Files.isDirectory(VERSIONS)) {
            System.out.println("No saved versions.");
            return;
        }

        List<Path> files;
        try (Stream<Path> stream = Files.list(VERSIONS)) {
            files = stream
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".yaml"))
                .sorted()
                .toList();
        }

        System.out.println("Saved versions: " + files.size());
        for (Path file : files) {
            System.out.println(file.getFileName() + " | " +
                               Files.size(file) + " bytes");
        }
    }
    private static void validateRules(Path file) throws Exception {
        Process process = new ProcessBuilder(
            ".venv/bin/python",
            "python/validate_rules.py",
            file.toString()
        ).inheritIO().start();

        int status = process.waitFor();
        if (status != 0) {
            throw new IOException(
                "Validation failed. Active rules were not replaced."
            );
        }
    }

    private static void restore(String version) throws Exception {
        if (!version.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) {
            throw new IllegalArgumentException("Invalid version name.");
        }

        Path source = VERSIONS.resolve(version + ".yaml");
        if (!Files.isRegularFile(source)) {
            throw new IOException("Version not found: " + version);
        }

        Path staged = Files.createTempFile(
            ACTIVE.toAbsolutePath().getParent(),
            "validated-rules-",
            ".tmp"
        );

        try {
            Files.copy(
                source,
                staged,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            );

            validateRules(staged);

            Path backup = null;
            if (Files.exists(ACTIVE)) {
                Path backupDir = Path.of("rules", "backups");
                Files.createDirectories(backupDir);

                backup = backupDir.resolve(
                    "before-restore-" + java.util.UUID.randomUUID() + ".yaml"
                );
                Files.copy(ACTIVE, backup);
            }

            Files.move(
                staged,
                ACTIVE,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            );

            System.out.println("Restored version: " + version);
            if (backup != null) {
                System.out.println("Previous rules backup: " + backup);
            }
            System.out.println("PASS: validated rules activated");
        } finally {
            Files.deleteIfExists(staged);
        }
    }


    public static void main(String[] args) {
        try {
            if (args.length == 2 && args[0].equals("snapshot")) {
                snapshot(args[1]);
            } else if (args.length == 2 && args[0].equals("restore")) {
                restore(args[1]);
            } else if (args.length == 1 && args[0].equals("list")) {
                listVersions();
            } else {
                System.err.println(
                    "Usage: RuleManager snapshot <version> | restore <version> | list"
                );
                System.exit(2);
            }
        } catch (Exception error) {
            System.err.println("Rule manager failed: " + error.getMessage());
            System.exit(1);
        }
    }
}

