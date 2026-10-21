import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
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

        validateRules(ACTIVE);
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
    private static void python(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(".venv/bin/python");
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).inheritIO().start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor();
            throw new IOException("Python helper timed out; active rules unchanged.");
        }
        if (process.exitValue() != 0) {
            throw new IOException("Python validation/codec failed; active rules unchanged.");
        }
    }

    private static void validateRules(Path file) throws Exception {
        python("python/validate_rules.py", file.toString());
    }

    private static Document loadYaml(Path path) throws Exception {
        Path xml = Files.createTempFile("rule-codec-", ".xml");
        try {
            python("python/rule_codec.py", "read", path.toString(), xml.toString());
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            return factory.newDocumentBuilder().parse(xml.toFile());
        } finally { Files.deleteIfExists(xml); }
    }

    private static List<Element> children(Element parent) {
        List<Element> result = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element) result.add((Element)n);
        }
        return result;
    }

    private static Element field(Element map, String name) {
        if (!map.getTagName().equals("map")) throw new IllegalArgumentException("Expected a rule object");
        for (Element entry : children(map)) {
            if (entry.getAttribute("key").equals(name)) return children(entry).get(0);
        }
        throw new IllegalArgumentException("Missing field: " + name);
    }

    private static Element ruleList(Document doc) {
        Element list = field(doc.getDocumentElement(), "rules");
        if (!list.getTagName().equals("list")) throw new IllegalArgumentException("rules must be a list");
        return list;
    }

    private static void saveYaml(Document doc, Path output) throws Exception {
        Path xml = Files.createTempFile("rule-codec-", ".xml");
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            factory.newTransformer().transform(new DOMSource(doc), new StreamResult(xml.toFile()));
            python("python/rule_codec.py", "write", xml.toString(), output.toString());
        } finally { Files.deleteIfExists(xml); }
    }

    private static void activate(Path staged, String reason) throws Exception {
        validateRules(staged);
        Path backups = ACTIVE.getParent().resolve("backups");
        Files.createDirectories(backups);
        Path backup = backups.resolve("before-" + reason + "-" + java.util.UUID.randomUUID() + ".yaml");
        Files.copy(ACTIVE, backup);
        Files.move(staged, ACTIVE, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Previous rules backup: " + backup);
    }

    // Candidate YAML is exactly one complete rule, including conditions.
    private static void addRule(Path candidate) throws Exception {
        validateRules(ACTIVE);
        Document current = loadYaml(ACTIVE);
        Document addition = loadYaml(candidate);
        Element rule = addition.getDocumentElement();
        Element name = field(rule, "name");
        for (Element old : children(ruleList(current))) {
            if (field(old, "name").getTextContent().equals(name.getTextContent())) {
                throw new IllegalArgumentException("Duplicate rule name");
            }
        }
        ruleList(current).appendChild(current.importNode(rule, true));
        Path staged = Files.createTempFile(ACTIVE.toAbsolutePath().getParent(), "new-rules-", ".tmp");
        try {
            saveYaml(current, staged);
            activate(staged, "add");
            System.out.println("PASS: rule added and validated");
        } finally { Files.deleteIfExists(staged); }
    }

    private static void listRules(String category) throws Exception {
        Document doc = loadYaml(ACTIVE);
        Element list = ruleList(doc);
        if (category != null) {
            // Encode the requested string through the same codec, avoiding a second JSON parser.
            Path query = Files.createTempFile("rule-category-", ".yaml");
            try {
                // YAML single quotes escape themselves by doubling.
                Files.writeString(query, "'" + category.replace("'", "''") + "'");
                String encoded = loadYaml(query).getDocumentElement().getTextContent();
                for (Element rule : children(list)) {
                    if (!field(rule, "category").getTextContent().equals(encoded)) list.removeChild(rule);
                }
            } finally { Files.deleteIfExists(query); }
        }
        Path output = Files.createTempFile("rule-list-", ".yaml");
        try {
            saveYaml(doc, output);
            System.out.print(Files.readString(output));
        } finally { Files.deleteIfExists(output); }
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


    private static void dispatch(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("snapshot")) snapshot(args[1]);
        else if (args.length == 2 && args[0].equals("restore")) restore(args[1]);
        else if (args.length == 2 && args[0].equals("add")) addRule(Path.of(args[1]));
        else if (args.length == 1 && args[0].equals("list")) listVersions();
        else if (args.length == 1 && args[0].equals("listRules")) listRules(null);
        else if (args.length == 2 && args[0].equals("findByCategory")) listRules(args[1]);
        else throw new IllegalArgumentException(
            "Usage: RuleManager snapshot VERSION | restore VERSION | list | listRules | add RULE.yaml | findByCategory CATEGORY");
    }

    public static void main(String[] args) {
        try {
            if (!Files.isRegularFile(ACTIVE)) throw new IOException("Run from project root; rules/rules.yaml missing");
            // Serialize all manager commands, including snapshot/restore, to avoid lost updates.
            try (FileChannel channel = FileChannel.open(ACTIVE.getParent().resolve(".manager.lock"),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock lock = channel.lock()) {
                if (!lock.isValid()) throw new IOException("Rules lock unavailable");
                dispatch(args);
            }
        } catch (Exception error) {
            System.err.println("Rule manager failed: " + error.getMessage());
            System.exit(1);
        }
    }
}
