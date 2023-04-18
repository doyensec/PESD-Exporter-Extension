/*
 * This template is based on the following specification documents:
 * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.Web%20Browser%20SSO%20Profile|outline
 * iin particular on section "5.1 Web Browser SSO Profile"
 * The section describes the typical flows likely to be used with the web browser SSO profile of SAML V2.0.
 * message flows involved in web SSO exchanges for the following use case scenarios:
 * - SP-initiated SSO using a Redirect Binding for the SP-to-IdP <AuthnRequest> message and a POST Binding for the IdP-to-SP <Response> message
 * - SP-initiated SSO using a POST Binding for the <AuthnRequest> message and an Artifact Binding for the <Response> message
 * - IDP-initiated SSO using a POST Binding for the IdP-to-SP <Response> message; no SP-to-IdP <AuthnRequest> message is involved.
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
