/*
 * This template attempts to add some GraphQL annotations to the output
 */
package pesd;

import java.io.PrintWriter;
import org.json.JSONObject;

public class GQL_Template extends TemplateParent{
    
    public GQL_Template( PESDWrapper pesdObj, PrintWriter stdout) {
        super(pesdObj, stdout);
    }
    
    @Override
    public PESDWrapper run(){
        Boolean is_Gql = false;
        pesdObj.startIterator();
        
        while (pesdObj.getIterator() != -1) {
            JSONObject line = pesdObj.getLine();
            JSONObject metadata;
            JSONObject bodyJson;
            
            switch((String) line.get("type")) {
                case "req":
                    try {
                        metadata = (JSONObject) line.get("metadata");
                        bodyJson = (JSONObject) metadata.get("body_json");

                        if (bodyJson.has("query") && metadata.getString("maskedPath").contains("graphql")) {
                          pesdObj.addFlag("GQL_Req", pesdObj.getIterator());
                          is_Gql = true;
                        }

                        if (bodyJson.has("query") && bodyJson.has("operationName")) {
                          pesdObj.addNote("GQL Operation Name: " + bodyJson.getString("operationName"), pesdObj.getIterator());
                        }
                    } catch(Exception e) {
                        this.stdout.println(e);
                    }
                    break;

                case "res":
                    if (is_Gql) {
                      pesdObj.addFlag("GQL_Res");
                      is_Gql = false;
                    }
                    break;
                    
                default: break;
            }
            pesdObj.nextLine();
        }
 
        return this.pesdObj;
    }
}
