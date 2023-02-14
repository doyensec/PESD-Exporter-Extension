/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package pesd;

import java.io.PrintWriter;
import org.json.JSONObject;

/**
 *
 * @author francesco lacerenza
 */
public class TemplateRunner {

    private PESDWrapper pesdObj;
    private final PrintWriter stdout;
    private TemplateParent template;
    private PESDWrapper[] templates_results;

    public TemplateRunner(String[] templates, PESDWrapper pesdObj, PrintWriter stdout) {
        this.stdout = stdout;
        this.pesdObj = pesdObj;
        //initializing copies (by value) of the exported pesdObj for the templates
        this.templates_results = new PESDWrapper[templates.length];
        for (int i = 0; i < templates.length; i++) {
            this.templates_results[i] = new PESDWrapper(this.stdout, pesdObj.getStucturedData());
        }

        Integer i = 0;
        for (String template : templates) {
            switch (template) {
                case "OAuth2/OIDC":
                    this.template = new Oauth2_OpenID_Template(this.templates_results[i], stdout);
                    break;
                case "SAML_SSO":
                    this.template = new SAML_SSO_Template(this.templates_results[i], stdout);
                    break;
                default:
                    this.template = null;
                    break;
            }
            if (this.template != null) {
                this.run(template, i);
                i++;
            }
        }
        // At this stage we have templates_result containing the normalized pesd objs for each template
        // we need to merge them in a final obj
        try {
            if (this.templates_results.length > 0) {
                for (PESDWrapper result : this.templates_results) {
                    this.pesdObj = mergeResults(this.pesdObj, result);
                }
            }
        } catch (Exception e) {
            stdout.println(e);
        }
    }

    public void run(String template, Integer i) {
        try {
            // executing the template i and saving its output
            this.templates_results[i] = this.template.run();
            // Before exiting we need to run altEndConsistencyNormalizer to solve local inconsistencies in the template resulting pesd obj
            // This is done to prevent MermaidJS rendering failure. Sometimes edge-cases within the templates execution may result
            // in Alt symbols without end symbols, viceversa or even mixed inconsistencies like two alt in a row.
            // This may happen due to non-standard flow implementation or other causes.
            // altEndConsistencyNormalizer removes such possible inconsistencies in the local result of the template.
            this.templates_results[i].altEndConsistencyNormalizer();
        } catch (Exception e) {
            stdout.println(e);
        }

    }

    public PESDWrapper mergeResults(PESDWrapper obj1, PESDWrapper obj2) {
        // Ordered merge of two pesd obj that are template results of the same starting-obj. As each template result has local consistency (thanks to altEndConsistencyNormalizer) and
        // it is originated from the same base obj, we can simply move Alt/end symbols from the shortest to the longest in an ordered way.
        // By doing so we generate the final result that will contain the matches of all the templates

        // we equalize the results in terms of length, simply by adding the Alt/end between the results 
        PESDWrapper first;
        PESDWrapper second;
        if (obj1.getSize() < obj2.getSize()) {
            first = obj2;
            second = obj1;
        } else {
            first = obj1;
            second = obj2;
        }
        equalizeAltEnd(first, second);
        return first;
    }

    public void equalizeAltEnd(PESDWrapper first, PESDWrapper second) {

        try {
            first.startIterator();
            second.startIterator();

            while (first.getIterator() != -1) {
                JSONObject line1 = first.getLine();
                JSONObject line2 = null;
                if (second.getIterator() != -1) {
                    line2 = second.getLine();
                    Boolean diff_type = (String) line1.get("type") != (String) line2.get("type");
                    Boolean second_is_alt = ((String) line2.get("type")).contains("alt");
                    Boolean second_is_end = ((String) line2.get("type")).contains("end");
                    Boolean first_is_alt = ((String) line1.get("type")).contains("alt");
                    Boolean first_is_end = ((String) line1.get("type")).contains("end");
                    // If types differ and second is alt or end, the line is inserted as first
                    if (diff_type) {
                        if (second_is_alt || second_is_end) {
                            first.addToPos(first.getIterator(), line2);
                        } else if (first_is_alt || first_is_end) {
                            second.addToPos(first.getIterator(), line1);
                        }
                    }
                } else {
                    second.addToPos(first.getIterator(), line1);
                }

                first.nextLine();
                second.nextLine();
            }
        } catch (Exception e) {
            stdout.println(e);
        }
    }

    public String[] getDiagram(Integer mode_op) {
        return this.pesdObj.getSeqDiagramdMD(mode_op);
    }

    public JSONObject getMetadata() {
        return this.pesdObj.getMetadata();
    }
}
