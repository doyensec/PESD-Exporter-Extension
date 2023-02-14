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

public class SAML_SSO_Template extends TemplateParent{
    
    public SAML_SSO_Template( PESDWrapper pesdObj, PrintWriter stdout) {
        super(pesdObj, stdout);
    }
    
    @Override
    public PESDWrapper run(){
        pesdObj.startIterator();
        // this boolean var will be set to false if a SAML request is found
        // that because IdP initiated SAML SSO are based on unsolicited SAML response directly sent to the SP from the IdP via HTML form Post
        Boolean is_IdP_Initiated = true;
        
        while (pesdObj.getIterator() != -1) {
            JSONObject line = pesdObj.getLine();
            JSONObject metadata;
            JSONObject urlParams;
            
            switch((String) line.get("type")){
                case "req":
                    try {
                        if (line.get("method") == "GET"){
                            metadata = (JSONObject) line.get("metadata");
                            urlParams = (JSONObject) metadata.get("url_params");

                            // SP-Initiated SSO with Redirect and POST Bindings
                            // // Identifying the SAML Request for SP-Initiated flow with redirect-Post bindings (flow's start)
                            if (urlParams.has("SAMLRequest")){
                                is_IdP_Initiated = false;
                                pesdObj.addFlag("SAMLRequest");
                                pesdObj.addAlt("SAML_SSO_SPI_Redirect_Post", pesdObj.getIterator()-2);

                            } else if (urlParams.has("SAMLResponse")) {
                                // Identifying the SAML Response for SP-Initiated flow with Post-Artifact bindings (flow's end)
                                pesdObj.addFlag("SAMLResponse");
                                pesdObj.endAlt(pesdObj.getIterator()+2);
                            }
                            
                            if (urlParams.has("RelayState")){
                                    pesdObj.addFlag("RelayState");
                                }
                        }
                    } catch(Exception e) {
                        stdout.println(e);
                    }
                    
                    try {
                        if (line.get("method") == "POST"){
                            metadata = (JSONObject) line.get("metadata");
                            JSONObject bodyParams = (JSONObject) metadata.get("body_params");
                            if (bodyParams.has("RelayState")){
                                pesdObj.addFlag("RelayState");
                            }
                            if (bodyParams.has("SAMLResponse")){
                                if (is_IdP_Initiated) {
                                    // if is_IdP_Initiated is true and we find a SAML Response, it means that we have an IdP initiated flow
                                    pesdObj.addAlt("SAML_SSO_IdP_initiated", pesdObj.getIterator()-2);
                                }
                                // Identifying the SAML Response for SP-Initiated flow with redirect-Post and Post-Artifact bindings (flow's end)
                                pesdObj.addFlag("SAMLResponse");
                                pesdObj.endAlt(pesdObj.getIterator()+2);
                            } else if (bodyParams.has("SAMLRequest")) {
                                // Identifying the SAML Request for SP-Initiated flow with POST-Artifact Binding  (flow's start)
                                is_IdP_Initiated = false;
                                pesdObj.addFlag("SAMLRequest");
                                pesdObj.addAlt("SAML_SSO_SPI__Post_Artifact", pesdObj.getIterator()-2);
                            }
                        }
                    } catch(Exception e) {
                        stdout.println(e);
                    }
                    break;

                default: break;
            }
            pesdObj.nextLine();
        }
        return this.pesdObj;
    }
}
