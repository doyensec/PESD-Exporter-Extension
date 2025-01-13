
<p align="center">
<img width="250" alt="pesd" src="https://user-images.githubusercontent.com/92733595/215836630-50bbb6cc-1623-4f78-a923-7ebb8db87608.png">
</p>


# PESD Exporter - Burp Suite Extension

Generate security-oriented sequence diagrams and fine-grained parsed traffic from Burp Suite Proxy history.  

This extension is based on the Proxy Enriched Sequence Diagrams (PESD) format.
Discover the format [here](mds/Format.md) and read the launch post on our [doyensec blog](https://blog.doyensec.com/2023/02/14/pesd-extension-public-release.html).

<p align="center">
<img width="1000" alt="extension" src="https://github.com/doyensec/PESD-Exporter-Extension/blob/main/images/burptopesd.gif">
</p>
The exporter handles Burp Suite Proxy's traffic conversion to PESD format and offers the possibility to execute templates that will enrich the resulting exports.

## Extension Usage 

Select and send specific traffic entries from Burp Suite Tabs to the Exporter tab. 

Specify a mode of operation for the export:

- **Domains as Actors** - Each domain involved in the traffic is represented as an actor in the diagram. Suitable for multi-domain flows analysis
- **Endpoints as Actors** - Each endpoint (path) involved in the traffic is represented as an actor in the diagram. Suitable for single-domain flows analysis

Auto-Export is enabled by default, sending items to the extension will directly result in a export. User is redirected to the Browser view and the items are cleaned after the export within the extension

## Export Capabilities

- **Expandable Metadata**. Underlined flags can be clicked to show the underlying metadata from the traffic in a scrollable popover
    
- **Masked Randoms in URL Paths**. UUIDs and pseudorandom strings recognized inside path segments are mapped to variable names `<UUID_N>` / `<VAR_N>`. The re-renderization will reshape the diagram to improve flow readability. Every occurrency with the same value maintains the same name
  
- **Notes**. Comments from Burp Suite are converted to notes in the resulting diagram. Use `<br>` in Burp Suite comments to obtain multi-line notes in PESD exports

- **Theme**. Use [MermaidJS theme](https://mermaid.js.org/config/theming.html?#theme-variables) veriables to build your own sequence diagram style set in the extension

- **Embedded MD editor**. Edit the generated diagram directly in the export to add details (e.g. internal calls to microservices, notes, everything allowed by mermaid JS)

- **Highlight colors from Burpsuite** are ported to the sequence diagram arrow colors

- **Invert Proxy History order**. If you have the last request on top, activate it

- **Save as** : `SVG`, `Markdown`, `JSON` metadata, explorable `HTML`
    
## Extending the diagram, syntax and metadata with Templates

By default, a generic diagram follows the basic [PESD syntax ](mds/Format.md#base-diagram-syntaxes).
PESD Exporter supports syntax and metadata extension via templates execution.

#### What is a Template?
Templates are iterations that occur on the basic PESD object in order to enrich its content by:
-	Adding new Flags or modifying existing ones
-	Framing sections of the resulting diagram. Read about [MermaidJS Alt Syntax](https://mermaid-js.github.io/mermaid/#/sequenceDiagram?id=alt). 
-	Enriching the metadata with new findings

***Approach Idea :*** Users can leverage this extensibility to parse metadata and markdown in order to add new value in both of them by adding new logic.

#### Currently Implemented Templates

The Extension currently supports the following templates :
-  **OAuth2 / OpenID Connect.** The template matches standard OAuth2/OpenID Connect flows and adds related flags + flow frame.
   Oauth2 supported flows : Implicit Grant and Code Grant. OpenID supported flows : Code Grant, Implicit Grant and Hybrid flow.
   Respectively based on [rfc6749](https://datatracker.ietf.org/doc/html/rfc6749) and [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html)

-  **SAML SSO**. The template matches Single-Sign-On flows with SAML V2.0 and adds related flags + flow frame.
    Based on [SAML V2.0 ](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.Web%20Browser%20SSO%20Profile|outline), supported flows:
	- SP-initiated SSO using a Redirect Binding for the SP-to-IdP <AuthnRequest> message and a POST Binding for the IdP-to-SP <Response> message
	- SP-initiated SSO using a POST Binding for the <AuthnRequest> message and an Artifact Binding for the <Response> message
	- IDP-initiated SSO using a POST Binding for the IdP-to-SP <Response> message; no SP-to-IdP <AuthnRequest> message is involved.

Template matching example for *SAML SP-initiated SSO with redirect POST*:
<p align="left">

<img width="550" alt="samlex" src="https://user-images.githubusercontent.com/92733595/218618497-a9c98b26-ed31-442d-8de7-a15fc3a8ec96.png">
</p>
	

#### Development

- Clone the repository
- Import it in Netbeans / your preferred IDE
- Run **gradle build fatjar** to compile the extension
- Import the compiled JAR in `build/libs/pesd-exporter-all.jar`
	
#### How to write new templates

Find the  [template implementation guide](mds/WritingTemplates.md).
	
## Credits

*Author and Maintainer:* Francesco Lacerenza ([@lacerenza_fra](https://twitter.com/lacerenza_fra))

This project was made with love in the [Doyensec Research island](https://doyensec.com/research.html) during the [internship with 50% research time](https://blog.doyensec.com/2019/11/05/internship-at-doyensec.html).

	

<img src='images/doyensec_logo.png' height='40px' alt='Doyensec Research'>
