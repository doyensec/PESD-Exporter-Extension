/*
 * This template is based on the following specification documents:
 * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 * https://openid.net/specs/openid-connect-core-1_0.html#Authentication
 */
package pesd;

import java.io.PrintWriter;
import java.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;

public class Oauth2_OpenID_Template extends TemplateParent{
    
    public Oauth2_OpenID_Template( PESDWrapper pesdObj, PrintWriter stdout) {
        super(pesdObj, stdout);
    }
    
    @Override
    public PESDWrapper run(){
        pesdObj.startIterator();
        while (pesdObj.getIterator() != -1) {
            JSONObject line = pesdObj.getLine();
            JSONObject metadata;
            JSONObject urlParams;
            
            switch((String) line.get("type")){
                case "req":
                    try {
                        metadata = (JSONObject) line.get("metadata");
                        urlParams = (JSONObject) metadata.get("url_params");

                        if (urlParams.has("client_id") && urlParams.has("response_type")){
                            // identifying first reqs of OpenID flow: code grant, token grant and hybrid
                            if (urlParams.has("scope") && urlParams.getString("scope").contains("openid")){
                                
                                if (urlParams.getString("response_type").contains("code") && urlParams.getString("response_type").contains("token")){
                                    // hybrid flow
                                    pesdObj.addFlag("OIDC_HybridGrant");
                                } else if (urlParams.getString("response_type").contains("code")) {
                                    // hybrid Code Grant flow
                                    pesdObj.addFlag("OIDC_CodeGrant");
                                } else if (urlParams.getString("response_type").contains("token")) {
                                    // implicit grant flow
                                    pesdObj.addFlag("OIDC_ImplicitGrant");
                                }
                                pesdObj.addAlt("OIDC", pesdObj.getIterator());
                            } else {
                                // identifying first reqs of OAuth2 flow: code grant and implicit grant
                                switch(urlParams.getString("response_type")){
                                    case "code":
                                        pesdObj.addFlag("CodeGrant");
                                        break;
                                    case "token":
                                        pesdObj.addFlag("ImplicitGrant");
                                        break;
                                    default:
                                        break;
                                }
                                pesdObj.addAlt("OAuth2", pesdObj.getIterator());
                            }
                        } 
                        //identifying last request of Code Grant flow
                        if (urlParams.has("code")){
                            pesdObj.addFlag("Code");
                            pesdObj.endAlt(pesdObj.getIterator()+2);
                        }
                    } catch(Exception e) {
                        stdout.println(e);
                    }
                    break;
                    
                case "res":
                    try {
                        //identifying last request of Implicit Grant flow
                        metadata = (JSONObject) line.get("metadata");
                        JSONArray headers = (JSONArray) metadata.get("headers");
                        for (int i = 0; i < headers.length(); i++) {
                            String header = headers.getString(i);
                            if (header.contains("Location") && header.contains("#") && header.contains("access_token") && header.contains("token_type")){
                                pesdObj.addFlag("AccessToken");
                                pesdObj.endAlt(pesdObj.getIterator()+1);
                            }
                        }
                        // looking for implicit grant tokens inside the response body
                        String raw_res_base64Encoded = (String) metadata.get("raw");
                        byte[] decodedBytes = Base64.getDecoder().decode(raw_res_base64Encoded);
                        String decoded_raw_response = new String(decodedBytes);
                        if(decoded_raw_response.contains("access_token") && decoded_raw_response.contains("token_type")){
                            pesdObj.addFlag("AccessToken");
                            pesdObj.endAlt(pesdObj.getIterator()+1);
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
