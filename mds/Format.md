# PESD Format

"Proxy Enriched Sequence Diagrams" is a simple format designed to leverage 
[MermaidJS](https://github.com/mermaid-js/mermaid) technology and link it with fine-grained web traffic parsing, to visualize and explore HTTP traffic in a new way.

## PESD Format
PESD is a diagramming format designed to visualize web traffic and store parsed information, usable for traffic analysis automation. It was created to reduce the efforts of IT / Security professionals when dealing with the complexity of functional flows in modern web applications.  

Some key characteristics of the format :
- Enable `visual-analysis`, especially useful for complex application flows in multi-actor scenarios
- `Tester-specific syntax` in order to facilitate the analysis
- Carry parsed metadata from the web traffic to `enable further automation of the analysis`
- Be `usable for reporting` purposes like documentation of current implementations or Proofs Of Concept

### Exports
A PESD export is composed of three elements :
- ***pesd.md*** , a markdown file containing the sequence diagram representing the intercepted web traffic. The markdown is based on [MermaidJS](https: github.com/mermaid-js/mermaid) syntax, a Javascript based diagramming and charting tool that renders Markdown-inspired text definitions to create and modify diagrams dynamically. Here is an example :

```
sequenceDiagram
Burp->>example.com:[GET] /favicon.ico<br>
example.com->>Burp:[404] HTML
```

MermaidJS rendered markdown:
<p align="left">
<img width="300" alt="pesd" src="https://user-images.githubusercontent.com/92733595/215847879-292ee8b8-4ef8-4423-84f6-3a0e5c4f1186.png">
</p>

- ***pesd.json*** , a JSON file containing parsed and raw data extracted from the traffic. This file represents the metadata of the format that enable further analysis automation and saving detailed flows

```
{
    "item1":{
		"req":{
            "path":"/favicon.ico",
            "headers":["[...] Array of Headers [...]"],
            "protocol":"http",
            "url_params":{},
            "port":80,
            "destination":"example.com",
            "raw":[...] BASE64ENCODED RAW REQUEST [...],
            "body_params":{},
            "id":1,
            "http-verb":"GET",
            "body_json":{},
            "cookies":{}
        },
		"templateMatches":{ ... },
        "res":{
            "Stated-MimeType":"HTML",
            "headers":[...] Array of Headers [...],
            "raw":"[...] BASE64ENCODED RAW RESPONSE [...]",
            "Inferred-MimeType":"HTML",
            "id":2,
            "cookies":{},
            "statusCode":404,
            "CSP": [...]CSP[...]
        }
    },
	.
	.
	.
	"itemN":{
		.
		.
		.
	}
}

```  

### Base Diagram Syntaxes

The traffic conversion syntax was defined on top of MermaidJS markdown syntax. The definition was designed to represent HTTP traffic with Sequence Diagrams.

Requests/responses arrows are filled with information that helps to visualize useful details of the traffic while maintaining the whole diagram readability.  

Two main modes of representation for application flows are supported:
- ***Domains as Actors*** - Each domain involved in the traffic is represented as an actor in the diagram. Suitable for multi-domain flows analysis
Current Syntax :
```
request message syntax : [HTTP.METHOD] /path/of/the/request
                            $Flag1$  $Flag2$ ... $FlagN$

response message syntax :  [Status.Code] Content-Type
                          $Flag1$  $Flag2$ ... $FlagN$
```

- ***Endpoints as Actors*** - Each endpoint (path) involved in the traffic is represented as an actor in the diagram. Suitable for single-domain flows analysis
Current Syntax :
```
request message syntax : [HTTP.METHOD] $Flag1$  $Flag2$ ... $FlagN$

response message syntax : [Status.Code] Content-Type $Flag1$  $Flag2$ ... $FlagN$
```

###### Flags 
Flags are basically Strings that represent the presence of something within req/res.
List of currently supported basic flags :
```
In Requests :
	-  HasCookies
	-  HasUrlParams
	-  HasBodyParams
	-  HasJsonParam
	-  HasXMLParam
	-  HasMultiPartAttr
	-  HasBearerToken
    	-  HasAuthz
In Responses :
	-  Content-Type
	-  CookiesSet
	-  HasCORS
	-  HasXFrameOption
	-  HasCSP

```

### How to generate PESD exports?

PESD can be generated directly from Burp Suite with the [PESD Exporter Extension](../README.md)

Alternatively, it is possible to use the [PESD Wrapper Java library](PESDWrapper.md).
The library exposes an object with all the methods needed to fill and modify a PESD Object. 
