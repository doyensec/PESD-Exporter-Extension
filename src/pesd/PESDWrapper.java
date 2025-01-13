/*
 * Proxy Enriched Sequence Diagrams Wrapper
 * This Object exposes all the needed methods to create / access / manipulate PESD: MD + Metadata
 *
 * @author Francesco Lacerenza from Doyensec
 */
package pesd;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import burp.IBurpExtenderCallbacks;
import org.json.JSONObject;
import org.json.JSONArray;

public class PESDWrapper {

    private JSONArray data;
    private int iterator;
    private boolean iterating;
    private HashMap<String, Integer> mappings;
    private final PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;

    public PESDWrapper(PrintWriter stdout, IBurpExtenderCallbacks callbacks) {
        // main constructor 
        this.stdout = stdout;
        this.callbacks = callbacks;
        
        try {
            this.data = new JSONArray();
            this.iterator = 0;
            this.mappings = new HashMap<>();
            this.iterating = false;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public PESDWrapper(PrintWriter stdout, JSONArray data) {
        // Constructor usable to create copies of a PESD Object, 
        // simply use getStucturedData() to extract JSONArray data and pass it to the constructor to create a clone
        this.data = data;
        this.stdout = stdout;
        this.iterator = 0;
        this.mappings = new HashMap<>();
        this.iterating = false;
    }

    public String[] getSeqDiagramdMD(Integer op_mode) {
        // This method serializes the data JSONArray to MermaidJS Markdown syntax

        // the Wrapper automatically checks and fixes the consistency of alt/end markdown symbols before exporting the MD
        // This is done to avoid garbage alt / end symbols from templates edge-cases that could break the MermaidJS Rendering of the MD
        this.altEndConsistencyNormalizer();
        //Note about op_mode:
        // 0 <- Domains as Actors
        // 1 <- Endpoints as Actors
        
        String seq_diagram_md = "sequenceDiagram\n";
        String seq_diagram_md_masked = "sequenceDiagram\n";
        this.startIterator();
        try {
        while (this.iterator != -1) {
            JSONObject line = this.getLine();
            String flags;
            switch ((String) line.get("type")) {
                case "req":
                    flags = this.flagsToStr((JSONArray) line.get("flags"));
                    if (op_mode == 0) {
                        seq_diagram_md += String.format("%s->>%s: [%s] %s<br>%s\n", line.get("source"), line.get("destination"), line.get("method"), escapeMermaid(line.get("path").toString()), flags);
                        seq_diagram_md_masked += String.format("%s->>%s: [%s] %s<br>%s\n", line.get("source"), line.get("destination"), line.get("method"), escapeMermaid(line.get("maskedPath").toString()), flags);
                    } else {
                            seq_diagram_md += String.format("%s->>%s: [%s] %s\n", line.get("source"), escapeMermaid(line.get("path").toString()), line.get("method"), flags);
                            seq_diagram_md_masked += String.format("%s->>%s: [%s] %s\n", line.get("source"), escapeMermaid(line.get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("method"), flags);
                    }
                    break;
                case "res":
                    flags = this.flagsToStr((JSONArray) line.get("flags"));
                    if (line.get("mime_type") == "NoNe") {
                        if (op_mode == 0) {
                            seq_diagram_md += String.format("%s->>%s: [%s] %s\n", line.get("source"), line.get("destination"), line.get("status_code"), flags);
                            seq_diagram_md_masked += String.format("%s->>%s: [%s] %s\n", line.get("source"), line.get("destination"), line.get("status_code"), flags);
                        } else if (this.getLine(this.iterator - 1).get("type") != "req") {
                            if (this.getLine(this.iterator - 2).get("type") != "req"){
                                seq_diagram_md += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 3).get("path").toString()), line.get("destination"), line.get("status_code"), flags);
                                seq_diagram_md_masked += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 3).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), flags);
                            } else {
                                seq_diagram_md += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 2).get("path").toString()), line.get("destination"), line.get("status_code"), flags);
                                seq_diagram_md_masked += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 2).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), flags);
                            }
                        } else {
                            seq_diagram_md += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 1).get("path").toString()), line.get("destination"), line.get("status_code"), flags);
                            seq_diagram_md_masked += String.format("%s->>%s: [%s] %s\n", escapeMermaid(this.getLine(this.iterator - 1).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), flags);
                        }
                    } else {
                        if (op_mode == 0) {
                            seq_diagram_md += String.format("%s->>%s: [%s] %s<br>%s\n", line.get("source"), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                            seq_diagram_md_masked += String.format("%s->>%s: [%s] %s<br>%s\n", line.get("source"), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                        } else if (this.getLine(this.iterator - 1).get("type") != "req") {
                            if (this.getLine(this.iterator - 2).get("type") != "req"){
                                seq_diagram_md += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 3).get("path").toString()), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                                seq_diagram_md_masked += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 3).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                            } else {
                                seq_diagram_md += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 2).get("path").toString()), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                                seq_diagram_md_masked += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 2).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                            }
                        } else {
                            seq_diagram_md += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 1).get("path").toString()), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                            seq_diagram_md_masked += String.format("%s->>%s: [%s] %s<br>%s\n", escapeMermaid(this.getLine(this.iterator - 1).get("maskedPath").toString()).replaceAll("<", "_").replaceAll(">", "_"), line.get("destination"), line.get("status_code"), line.get("mime_type"), flags);
                        }

                    }
                    break;
                case "alt":
                    seq_diagram_md += String.format("Alt %s\n", line.get("alt"));
                    seq_diagram_md_masked += String.format("Alt %s\n", line.get("alt"));
                    break;
                case "end":
                    seq_diagram_md += "end\n";
                    seq_diagram_md_masked += "end\n";
                    break;
                case "note":
                    seq_diagram_md += String.format("Note right of Browser : %s\n", line.get("note"));
                    seq_diagram_md_masked += String.format("Note right of Browser : %s\n", line.get("note"));
                    break;
                default:
                    break;
            }
            this.nextLine();
        }
        } catch (Exception e) {
                this.stdout.println("error : "+e.toString());
            }
        return new String[]{seq_diagram_md, seq_diagram_md_masked};
    }

    private String flagsToStr(JSONArray flagsArr) {
        // serialize flags array to a string that will be added to the transaction in the MD
        String flags = "";
        for (int i = 0; i < flagsArr.length(); i++) {
            flags += String.format(" %s ", flagsArr.getString(i));
        }
        return flags;
    }

    public JSONObject getMetadata() {
        // Creating metadata export with PESD format

        JSONObject metadata = new JSONObject();
        Integer item_num = 1;
        JSONObject item;
        this.startIterator();
        while (this.iterator != -1) {
            try {
                item = new JSONObject();
                if ((String) this.getLine().get("type") == "req") {
                    JSONObject line_metadata = (JSONObject) this.getLine().get("metadata");
                    item.put("req", line_metadata);
                    if ((String) this.getLine(this.iterator + 1).get("type") == "res") {
                        item.put("res", (JSONObject) this.getLine(this.iterator + 1).get("metadata"));
                        this.setIterator(this.iterator + 2);
                    } else if ((String) this.getLine(this.iterator + 2).get("type") == "res" && (String) this.getLine(this.iterator + 1).get("type") != "req"){
                        item.put("res", (JSONObject) this.getLine(this.iterator + 2).get("metadata"));
                        this.setIterator(this.iterator + 3);
                    } else if((String) this.getLine(this.iterator + 3).get("type") == "res" && (String) this.getLine(this.iterator + 2).get("type") != "req" && (String) this.getLine(this.iterator + 1).get("type") != "req"){
                        item.put("res", (JSONObject) this.getLine(this.iterator + 3).get("metadata"));
                        this.setIterator(this.iterator + 4);
                     } else {
                        this.nextLine();
                    }
                    metadata.put("item" + item_num, item);
                    item_num++;
                } else {
                    this.nextLine();
                }
            } catch (Exception e) {
                this.nextLine();
            }
        }
        return metadata;
    }

    public JSONObject getLine() {
        return (JSONObject) this.data.get(this.iterator);
    }

    public JSONObject getLine(Integer index) {
        if (!(index > (this.data.length() - 1))) {
            return (JSONObject) this.data.get(index);
        } else {
            JSONObject errorLine = new JSONObject();
            errorLine.put("type", "error");
            return errorLine;
        }
    }

    public Integer getIterator() {
        return this.iterator;
    }

    public void setIterator(Integer num) {
        if (!(num > (this.data.length() - 1))) {
            this.iterator = num;
        } else {
            this.iterator = -1;
        }
    }

    public void startIterator() {
        this.iterator = 0;
        this.iterating = true;
    }

    public void startIterator(Integer num) {
        this.iterator = num;
        this.iterating = true;
    }

    public void nextLine() {
        if ((this.iterator + 1) > (this.data.length() - 1)) {
            this.iterator = -1;
            this.iterating = false;
        } else {
            this.iterator++;
        }
    }

    public void prevLine() {
        if (this.iterator > 0) {
            this.iterator--;
        }
    }

    public void addReq(String source, String destination, String method, String path, List<String> flags, JSONObject metadata) {
        // Method used to add a Request line to the obj that will have the format:
        // Markdown :  S ->> D : [METHOD] /path \n Flag1 Flag2 ... FlagN
        // Metadata: JSONObject generated by PESDMetadata obj

        JSONObject line = new JSONObject();
        line.put("type", "req");
        line.put("source", source);
        line.put("destination", destination);
        line.put("method", method);
        line.put("path", path);
        line.put("flags", flags);
        String maskedPath = pathMapper(path);
        metadata.put("maskedPath", maskedPath);
        line.put("maskedPath", maskedPath);
        line.put("metadata", metadata);
        this.data.put(line);
    }

    public void addReq(String source, String destination, String method, String path, List<String> flags, JSONObject metadata, Integer index) {
        // Same as normal addReq, but to a specific index

        JSONObject line = new JSONObject();
        line.put("type", "req");
        line.put("source", source);
        line.put("destination", destination);
        line.put("method", method);
        line.put("path", path);
        line.put("flags", flags);
        String maskedPath = pathMapper(path);
        metadata.put("maskedPath", maskedPath);
        line.put("metadata", metadata);
        addToPos(index, line);

        if (this.iterating & index <= this.iterator) {
            this.iterator++;
        }
    }

    public void addRes(String source, String destination, String status_code, String mimeType, List<String> flags, JSONObject metadata) {
        // Method used to add a Response line to the obj that will have the format:
        // Markdown :  D ->> S : [STATUS_CODE] MIME_TYPE \n Flag1 Flag2 ... FlagN
        // Metadata: JSONObject generated by PESDMetadata obj

        JSONObject line = new JSONObject();
        line.put("type", "res");
        line.put("source", source);
        line.put("destination", destination);
        line.put("status_code", status_code);
        line.put("mime_type", mimeType);
        line.put("flags", flags);
        line.put("metadata", metadata);
        this.data.put(line);
    }

    public void addRes(String source, String destination, String status_code, String mimeType, List<String> flags, JSONObject metadata, Integer index) {
        // Same as normal addRes, but to a specific index

        JSONObject line = new JSONObject();
        line.put("type", "res");
        line.put("source", source);
        line.put("destination", destination);
        line.put("status_code", status_code);
        line.put("mime_type", mimeType);
        line.put("flags", flags);
        line.put("metadata", metadata);
        addToPos(index, line);

        if (this.iterating & index <= this.iterator) {
            this.iterator++;
        }
    }

    public void addAlt(String text) {
        // Method used to add a Alt line (rectangle start in MermaidJS MD) to the obj that will have the format :
        // Markdown :  Alt NAME

        JSONObject line = new JSONObject();
        line.put("type", "alt");
        line.put("alt", text);
        this.data.put(line);
    }

    public void addAlt(String text, Integer index) {
        // Same as normal addAlt, but to a specific index

        JSONObject line = new JSONObject();
        line.put("type", "alt");
        line.put("alt", text);
        addToPos(index, line);

        if (this.iterating & index <= this.iterator) {
            this.iterator++;
        }
    }

    public void endAlt() {
        // Method used to add a end line (rectangle close in MermaidJS MD) to the obj that will have the format :
        // Markdown :  end

        JSONObject line = new JSONObject();
        line.put("type", "end");
        this.data.put(line);
    }

    public void endAlt(Integer index) {
        // Same as normal endAlt, but to a specific index
        JSONObject line = new JSONObject();
        line.put("type", "end");
        addToPos(index, line);

        if (this.iterating & index <= this.iterator) {
            this.iterator++;
        }
    }

    public void addNote(String note) {
        // Method used to add a Note line to the obj that will have the format:
        // Markdown :  Note right of Browser : TEXT

        JSONObject line = new JSONObject();
        line.put("type", "note");
        line.put("note", note);
        this.data.put(line);
    }

    public void addNote(String note, Integer index) {
        // Same as normal addNote, but to a specific index

        JSONObject line = new JSONObject();
        line.put("type", "note");
        line.put("note", note);
        addToPos(index, line);

        if (this.iterating & index <= this.iterator) {
            this.iterator++;
        }
    }

    public void modifyFlags(List<String> flagsArr) {
        // substituting flags in a transaction during an iteration 

        if (this.iterating) {
            JSONObject line = (JSONObject) this.data.get(this.iterator);
            line.remove("flags");
            line.put("flags", flagsArr);
        }
    }

    public void modifyFlags(List<String> flagsArr, Integer index) {
        // Same as normal modifyFlags, but to a specific index

        JSONObject line = (JSONObject) this.data.get(index);
        line.remove("flags");
        line.put("flags", flagsArr);
    }

    public void addFlag(String flag) {
        // adding a flag to a transaction while iterating

        JSONArray flags = (JSONArray) this.getLine().get("flags");
        List<String> list = new ArrayList<String>();
        for (int i = 0; i < flags.length(); i++) {
            list.add(flags.getString(i));
        }
        list.add(String.format(" %s ", flag));
        this.modifyFlags(list);
    }

    public void addFlag(String flag, Integer index) {
        // Same as normal addFlag, but to a specific index

        JSONArray flags = (JSONArray) this.getLine(index).get("flags");
        List<String> list = new ArrayList<String>();
        for (int i = 0; i < flags.length(); i++) {
            list.add(flags.getString(i));
        }
        list.add(String.format(" %s ", flag));
        this.modifyFlags(list);
    }

    public void modifyMetadata(JSONObject metadataObj) {
        // Replacing a metadata object in a line with new metadata while iterating

        if (this.iterating) {
            JSONObject line = (JSONObject) this.data.get(this.iterator);
            line.remove("metadata");
            line.put("metadata", metadataObj);
        }
    }

    public void modifyMetadata(JSONObject metadataObj, Integer index) {
        // Same as normal modifyMetadata, but to a specific index

        JSONObject line = (JSONObject) this.data.get(index);
        line.remove("metadata");
        line.put("metadata", metadataObj);
    }

    public void removeLine() {
        // remove line while iterating

        if (this.iterating) {
            this.data.remove(this.iterator);
            this.iterator--;
        }
    }

    public void removeLine(Integer index) {
        //remove line on at a specific index

        JSONObject a = (JSONObject) this.data.remove(index);
        if (this.iterating & index <= this.iterator) {
            this.iterator--;
        }
    }

    public Boolean altEndConsistencyNormalizer() {
        // This method is used to resolve local consistency problems within the resulting MermaidJS Markdown before the serialization
        // Currently it simply remove non-closed  and non-opened Alt rectangles (Alt without end or end without Alt)  
        // Moreover, in case of 2 consecutive Alt, the first occurrence is removed

        try {
            this.startIterator();
            Integer lastAlt = -1;
            while (this.getIterator() != -1) {
                switch (this.getLine().getString("type")) {
                    case "alt":
                        if (lastAlt != -1) {
                            this.removeLine(lastAlt);
                            lastAlt = this.getIterator();
                        } else {
                            lastAlt = this.getIterator();
                        }
                        break;
                    case "end":
                        if (lastAlt != -1) {
                            lastAlt = -1;
                        } else {
                            this.removeLine();
                        }
                        break;
                    default:
                        break;
                }
                this.nextLine();
            }
            if (lastAlt != -1) {
                this.removeLine(lastAlt);
            }
        } catch (Exception e) {
            stdout.println("Error:" + e.toString());
            return false;
        }
        return true;
    }

    public void addToPos(int pos, JSONObject jsonObj) {
        // Function needed to perform JSONArray.put(pos, json) without losing an entry due to replacement.
        // Basically it performs right-shift of all the entries after the position needed for the put

        for (int i = this.data.length(); i > pos; i--) {
            this.data.put(i, this.data.get(i - 1));
        }
        this.data.put(pos, jsonObj);
    }

    public Integer getSize() {
        return this.data.length();
    }

    public JSONArray getStucturedData() {
        // returns a copy by value of the data contained in the wrapper

        return new JSONArray(this.data);
    }

    public String escapeMermaid(String input) {
        // encoding segments to avoid renderization errors
        
        String[] segments = input.split("/");
        if (segments.length == 0) {
            return "/";
        }
        for (int i = 0; i < segments.length; i++) {
            if (!segments[i].matches("^<VAR_..?>") && !segments[i].matches("^<UUID_..?>")) {
                segments[i] = java.net.URLEncoder.encode(segments[i]);
            }
        }
        return String.join("/", segments);
    }

    public String pathMapper(String path) {
        // the function splits the path and checks if segments contain UUIDs or pseudorandom strings.
        // If spotted they are added to an internal map for future occurrences and substituted with placeholders in the returned string
        
        String[] segments = path.split("/");
        if (segments.length == 0) {
            return "/";
        }

        for (int i = 0; i < segments.length; i++) {
            if (uuidTest(segments[i]) || maskTest(segments[i])) {
                if (!this.mappings.containsKey(segments[i])) {
                    this.mappings.put(segments[i], this.mappings.size() + 1);
                    segments[i] = substituteMask(segments[i]);
                } else {
                    segments[i] = substituteMask(segments[i]);
                }
            }

        }
        return String.join("/", segments);
    }

    public String substituteMask(String segment) {
        // returns the needed placeholder according to the passed rand 
        if (uuidTest(segment)) {
            return String.format("<UUID_%d>", this.mappings.get(segment));
        } else {
            return String.format("<VAR_%d>", this.mappings.get(segment));
        }
    }

    public Boolean uuidTest(String input) {
        try {
            UUID uuid = UUID.fromString(input);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public Boolean maskTest(String input) {
        // this function is used to evaluate the presence of a pseudorandom string in a URL path segment
        // The simple approach combines three elements: Shannon entropy + sliding charset len + segment len

        int numChars = 0;
        int upper = 0, lower = 0, number = 0, special = 0;

        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (ch >= 'A' && ch <= 'Z') {
                upper++;
            } else if (ch >= 'a' && ch <= 'z') {
                lower++;
            } else if (ch >= '0' && ch <= '9') {
                number++;
            } else {
                special++;
            }
        }
        if (upper > 0) {
            numChars = numChars + 26;
        }
        if (lower > 0) {
            numChars = numChars + 26;
        }
        if (special > 0) {
            numChars = numChars + 5;
        }
        // Calculate the Shannon entropy of the input string

        HashMap<Character, Integer> frequencyMap = new HashMap<>();

        // Iterate through each character in the input string
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (!frequencyMap.containsKey(c)) {
                // If the character is not in the map, add it with a frequency of 1
                frequencyMap.put(c, 1);
            } else {
                // If the character is already in the map, increment its frequency
                frequencyMap.put(c, frequencyMap.get(c) + 1);
            }
        }

        // Initialize the entropy value to 0
        double entropy = 0;

        // Iterate through each character in the frequency map
        for (char c : frequencyMap.keySet()) {
            // Calculate the probability of the character in the input string
            double probability = (double) frequencyMap.get(c) / input.length();

            // Add the contribution of the character to the entropy
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        // Calculate the maximum entropy for a string of the same length and character set
        double maxEntropy = Math.log(numChars) / Math.log(2);

        // Compare the calculated entropy to the maximum entropy
        double entropyRatio = entropy / maxEntropy;

        // If the entropy ratio is close to 1, the input string is considered random
        if (entropyRatio >= 0.90) {
            return true;
        }

        if (input.length() > 18 && entropyRatio > 0.80) {
            if (number > 0 && special > 0) {
                return true;
            }
        }

        if (input.length() > 25 && number > 0 && (upper > 0 || special > 0) && entropyRatio > 0.70) {
            return true;
        }

        if (input.length() > 35) {
            return true;
        }

        return false;

    }

}
