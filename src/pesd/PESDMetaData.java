
package pesd;

import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
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
public class PESDMetaData {

    private final IExtensionHelpers helpers;

    public PESDMetaData(IExtensionHelpers helpers) {
        this.helpers=helpers;
    }
    
    public JSONObject addItemMetadata(Integer num, String path, IRequestInfo iRequestInfo, IResponseInfo iResponseInfo, IHttpRequestResponse reqResItem, JSONObject url_params, JSONObject body_params, JSONObject body_json, String CSP, JSONObject req_cookies, Boolean noRes) {
        JSONObject item = new JSONObject();
        //adding req json key
        JSONObject req = new JSONObject();
        req.put("id",num);
        req.put("destination",StringEscapeUtils.escapeJava(reqResItem.getHttpService().getHost()));
        req.put("protocol",StringEscapeUtils.escapeJava(reqResItem.getHttpService().getProtocol()));
        req.put("port",reqResItem.getHttpService().getPort());
        req.put("path",StringEscapeUtils.escapeJava(path));
        req.put("raw", helpers.base64Encode(reqResItem.getRequest()));
        req.put("http-verb",iRequestInfo.getMethod());
        List<String> req_headers=iRequestInfo.getHeaders();
        List<String> req_headers_escaped= new ArrayList<String>();
        for (String header : req_headers){
            req_headers_escaped.add(StringEscapeUtils.escapeJava(header));
        }
        req.put("headers",req_headers_escaped);
        //Escaped in PESDExporter
        req.put("url_params",url_params);
        //Escaped in PESDExporter
        req.put("body_params",body_params);
        //Escaped in PESDExporter
        req.put("body_json",body_json);
        //Escaped in PESDExporter
        req.put("cookies",req_cookies);
        //add highlight, comment keys
        req.put("highlight",reqResItem.getHighlight());
        req.put("comment", StringEscapeUtils.escapeJava(reqResItem.getComment()));
        
        item.put("req",req);
        
        if (!noRes){
            //adding res json key
            JSONObject res = new JSONObject();
            
            res.put("id",num+1);
            res.put("statusCode",iResponseInfo.getStatusCode());
            res.put("raw",helpers.base64Encode(reqResItem.getResponse()));
            res.put("Inferred-MimeType",StringEscapeUtils.escapeJava(iResponseInfo.getInferredMimeType()));
            res.put("Stated-MimeType",StringEscapeUtils.escapeJava(iResponseInfo.getStatedMimeType()));
            if (!CSP.isEmpty()){res.put("CSP",StringEscapeUtils.escapeJava(CSP));}
            List<String> res_headers=iResponseInfo.getHeaders();
            List<String> res_headers_escaped= new ArrayList<String>();
            for (String header : res_headers){
                res_headers_escaped.add(StringEscapeUtils.escapeJava(header));
            }
            res.put("headers",res_headers_escaped);
            
            
            JSONObject res_cookies_escaped = new JSONObject();
            List<ICookie> iCookie = iResponseInfo.getCookies();
            for (ICookie cookie : iCookie){
                res_cookies_escaped.put(StringEscapeUtils.escapeJava(cookie.getName()),StringEscapeUtils.escapeJava(cookie.getValue()));
            }
            res.put("cookies",res_cookies_escaped);
            item.put("res",res);
        }
        
        return item;
    }
    
}
