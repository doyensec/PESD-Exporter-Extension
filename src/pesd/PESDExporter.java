package pesd;

import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import java.io.PrintWriter;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;
import org.apache.commons.lang3.StringEscapeUtils;

/**
 *
 * @author francesco
 */
public class PESDExporter {

    private IExtensionHelpers helpers;
    private IHttpRequestResponse[] allReqRes;
    private PrintWriter stdout;
    private Integer operationMode;
    private Boolean[] wantedBools;
    private String metadata;
    private JSONObject metadataObj;
    private String[] templates;
    private IBurpExtenderCallbacks callbacks;

    public PESDExporter(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, IHttpRequestResponse[] allReqRes, PrintWriter stdout, PrintWriter stderr, Integer mode, Boolean[] syntaxBools, String[] templates) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.allReqRes = allReqRes;
        this.stdout = stdout;
        // op. mode = 0 -> Domains as Actors , op. mode = 1 -> Endpoints as Actors
        this.operationMode = mode;
        // Selected template
        this.templates = templates;
        // wantedBools index: 0=HasUrlParams, 1=HasBodyParam, 2=HasJsonParam, 3=HasXmlParam, 4=HasMultipartAttr, 5=HasAuthzToken, 6=Content-type, 7=CookiesSet, 8=HasCORS, 9=HasXFrameOp, 10=HasCSP, 11=HasCookies
        this.wantedBools = syntaxBools;
    }

    public String[] generatePESD() {
        JSONObject csp_res;
        String CSP = "";
        PESDWrapper pesdObj = new PESDWrapper(this.stdout, this.callbacks);
        // PESDMetaData will handle data addition to the metadata
        PESDMetaData metadataObj = new PESDMetaData(this.helpers);
        //Looping over all req/res couples (items) and converting them to PESD markdown and metadata
        int num = 1;
        String browser = "Browser";
        for (int rc = 0; rc < this.allReqRes.length; rc++) {
            try {
                //needed items parsing vars
                Boolean noRes = false;
                IResponseInfo iResponseInfo = new IResponseInfo() {
                    @Override
                    public List<String> getHeaders() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public int getBodyOffset() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public short getStatusCode() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ICookie> getCookies() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public String getStatedMimeType() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public String getInferredMimeType() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                };

                IHttpService httpService = allReqRes[rc].getHttpService();
                String actor = httpService.getHost();
                IRequestInfo iRequestInfo2 = helpers.analyzeRequest(allReqRes[rc]);
                String path = iRequestInfo2.getUrl().getPath();
                IRequestInfo iRequestInfo = helpers.analyzeRequest(allReqRes[rc].getRequest());
                try {
                    iResponseInfo = helpers.analyzeResponse(allReqRes[rc].getResponse());
                } catch (Exception e) {
                    noRes = true;
                }

                JSONObject params_res = this.getParamsSetFlag(iRequestInfo);
                // getting params lists: url, body, json, cookies, csp
                JSONObject url_params = params_res.getJSONObject("url_params");
                JSONObject body_params = params_res.getJSONObject("body_params");
                JSONObject body_json = params_res.getJSONObject("body_json");
                JSONObject req_cookies = params_res.getJSONObject("req_cookies");
                if (!noRes) {
                    csp_res = this.getHasCSPFlag(iResponseInfo);
                    csp_res.getBoolean("HasCSP");
                    CSP = csp_res.getString("CSP");
                }
                // adding metadata about the item
                JSONObject metadata_item = metadataObj.addItemMetadata(num, path, iRequestInfo, iResponseInfo, allReqRes[rc], url_params, body_params, body_json, CSP, req_cookies, noRes);
                num = num + 2;
                List<String> flags_req = aggregateReqFlags(iRequestInfo);
                pesdObj.addReq(browser, actor, iRequestInfo.getMethod(), path, flags_req, (JSONObject) metadata_item.get("req"));
                try {
                    if (!metadata_item.getJSONObject("req").get("comment").toString().isEmpty()) {
                        pesdObj.addNote(metadata_item.getJSONObject("req").get("comment").toString());
                    }
                } catch (Exception e) {
                }

                //Handling items with response 
                if (!noRes) {

                    List<String> flags_res = aggregateResFlags(iResponseInfo);
                    String mime_type;
                    if (this.wantedBools[6]) {
                        mime_type = iResponseInfo.getStatedMimeType();
                    } else {
                        mime_type = "NoNe";
                    }
                    pesdObj.addRes(actor, browser, String.valueOf(iResponseInfo.getStatusCode()), mime_type, flags_res, (JSONObject) metadata_item.get("res"));
                } else {
                    num = num - 1;
                }

            } catch (Exception e) {
                stdout.println("Error:" + e.toString());
            }
        }
        //template engine run
        TemplateRunner engine = new TemplateRunner(this.templates, pesdObj, this.stdout);
        this.metadata = engine.getMetadata().toString();
        this.metadataObj = engine.getMetadata();
        return engine.getDiagram(this.operationMode);
    }

    public String getMetadata() {
        return this.metadata;
    }

    private Boolean getCookiesSetFlag(IResponseInfo iResponseInfo) {
        // CookieSet Boolean
        Boolean CookiesSet = false;
        List<ICookie> iCookie = iResponseInfo.getCookies();
        if (iCookie.size() != 0 && this.wantedBools[7]) {
            CookiesSet = true;
        }
        return CookiesSet;
    }

    private Boolean getHasAuthzFlag(IRequestInfo iRequestInfo) {
        Boolean HasAuthz = false;
        if (this.wantedBools[5]) {
            List<String> headers = iRequestInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().replaceAll("\\s", "").startsWith("authorization")) {
                    HasAuthz = true;
                    break;
                }
            }
        }
        return HasAuthz;
    }

    private JSONObject getParamsSetFlag(IRequestInfo iRequestInfo) {
        JSONObject results = new JSONObject();
        Boolean PramBools[] = new Boolean[]{false, false, false, false, false, false};
        // Params Flags parsing and arranging for metadata 
        // Bools index: 0=HasUrlParams, 1=HasBodyParam, 2=HasJsonParam, 3=HasXmlParam, 4=HasMultipartAttr, 5=HasAuthzToken, 6=Content-type, 7=CookiesSet
        // array of output bools ordered with true val if one of the types matches in one param, IParameter inteface types value : PARAM_URL=0, PARAM_BODY=1, PARAM_JSON=6, PARAM_XML=3, PARAM_MULTIPART_ATTR=5, PARAM_COOKIE=2 
        List<IParameter> iParameter = iRequestInfo.getParameters();
        JSONObject url_params = new JSONObject();
        JSONObject body_params = new JSONObject();
        JSONObject body_json = new JSONObject();
        JSONObject req_cookies = new JSONObject();

        for (int i = 0; i < iParameter.size(); i++) {
            switch (iParameter.get(i).getType()) {
                case 0:
                    if (this.wantedBools[0]) {
                        PramBools[0] = true;
                        //URL . use getname and getvalue then add it to a list
                        String name = iParameter.get(i).getName();
                        String value = iParameter.get(i).getValue();
                        url_params.put(StringEscapeUtils.escapeJava(name), StringEscapeUtils.escapeJava(value));
                    }
                    break;
                case 2:
                    if (this.wantedBools[11]) {
                        PramBools[5] = true;
                        //Cookie . use getname and getvalue then add it to a list
                        String name = iParameter.get(i).getName();
                        String value = iParameter.get(i).getValue();
                        req_cookies.put(StringEscapeUtils.escapeJava(name), StringEscapeUtils.escapeJava(value));
                    }
                    break;
                case 1:
                    if (this.wantedBools[1]) {
                        PramBools[1] = true;
                        //BodyParam . use getname and getvalue then add it to a list
                        String name = iParameter.get(i).getName();
                        String value = iParameter.get(i).getValue();
                        body_params.put(StringEscapeUtils.escapeJava(name), StringEscapeUtils.escapeJava(value));
                    }
                    break;
                case 6:
                    if (this.wantedBools[2]) {
                        PramBools[2] = true;
                        //bodyJSON . use getname and getvalue then add it to a list
                        String name = iParameter.get(i).getName();
                        String value = iParameter.get(i).getValue();
                        body_json.put(StringEscapeUtils.escapeJava(name), StringEscapeUtils.escapeJava(value));
                    }
                    break;
                case 3:
                    if (this.wantedBools[3]) {
                        PramBools[3] = true;
                    }
                    break;
                case 5:
                    if (this.wantedBools[4]) {
                        PramBools[4] = true;
                    }
                    break;
                default:
                    break;
            }
        }
        results.put("ParamBools", PramBools);
        results.put("url_params", url_params);
        results.put("body_params", body_params);
        results.put("body_json", body_json);
        results.put("req_cookies", req_cookies);
        return results;
    }

    private Boolean getHasXFrameOpFlag(IResponseInfo iResponseInfo) {
        Boolean HasXFrameOp = false;
        List<String> headers = iResponseInfo.getHeaders();
        if (this.wantedBools[9]) {
            for (String header : headers) {
                if (header.startsWith("X-Frame-Options")) {
                    HasXFrameOp = true;
                    break;
                }
            }
        }
        return HasXFrameOp;
    }

    private JSONObject getHasCSPFlag(IResponseInfo iResponseInfo) {
        JSONObject result = new JSONObject();
        String CSP_string = "";
        Boolean HasCSP = false;
        List<String> headers = iResponseInfo.getHeaders();
        if (this.wantedBools[10]) {
            for (String header : headers) {
                if (header.startsWith("Content-Security-Policy")) {
                    HasCSP = true;
                    CSP_string = header;
                    break;
                }
            }
        }
        result.put("HasCSP", HasCSP);
        result.put("CSP", CSP_string);
        return result;
    }

    private Boolean getHasCORSFlag(IResponseInfo iResponseInfo) {
        Boolean HasCORS = false;
        List<String> headers = iResponseInfo.getHeaders();
        if (this.wantedBools[8]) {
            for (String header : headers) {
                if (header.startsWith("Access-Control-Allow-Origin")) {
                    HasCORS = true;
                    break;
                }
            }
        }
        return HasCORS;
    }

    private List<String> aggregateReqFlags(IRequestInfo iRequestInfo) {
        // ParamBools is an array of bools ordered with true val if one of the types matches in one param: PARAM_URL=0, PARAM_BODY=1, PARAM_JSON=6, PARAM_XML=3, PARAM_MULTIPART_ATTR=5 , PARAM_COOKIE=2
        String PramFlags[] = new String[]{"UrlParams", "BodyParams ", "JSONParam", "XMLParam", "Multipart", "Cookies"};
        List<String> paramBools = new ArrayList<String>();
        Boolean[] params = (Boolean[]) this.getParamsSetFlag(iRequestInfo).get("ParamBools");
        for (int i = 0; i < 6; i++) {
            if (params[i] == true) {
                paramBools.add(PramFlags[i]);
            }
        }
        if (this.getHasAuthzFlag(iRequestInfo)) {
            paramBools.add("HasAuthz");
        }
        return paramBools;
    }

    private List<String> aggregateResFlags(IResponseInfo iResponseInfo) {
        List<String> resBools = new ArrayList<String>();
        if (this.getCookiesSetFlag(iResponseInfo)) {
            resBools.add("SetCookies");
        }
        if (this.getHasCORSFlag(iResponseInfo)) {
            resBools.add("CORS");
        }
        if (this.getHasXFrameOpFlag(iResponseInfo)) {
            resBools.add("XFrameOp");
        }
        JSONObject csp_res = this.getHasCSPFlag(iResponseInfo);
        if (csp_res.getBoolean("HasCSP")) {
            resBools.add("CSP");
        }
        return resBools;
    }

}
