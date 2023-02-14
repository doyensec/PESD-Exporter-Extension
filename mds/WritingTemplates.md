
## How to write templates

Required Steps :

#### 1) Develop your template 
In order to manipulate the pesd object you should read the [PESD Wrapper Java library](PESDWrapper.md) documentation and learn about all the exposed iteration / manipulation methods.

Templates must inherit from **TemplateParent** and override the *Run* method. The engine will construct all the templates and save them in a TemplateParent var, then it will call the *Run* method to manipulate the *PESDWrapper* object.

The following code is an Empty Template structure to start with:
```
/*
 * Empty Template Structure
 */
 
public class EmptyTemplate extends TemplateParent{
    // As you can see, the creation will set pesdObj and stdout to be accessible directly within your code
    public EmptyTemplate( PESDWrapper pesdObj, PrintWriter stdout) {
        super(pesdObj, stdout);
    }
	
    // put all your logic inside the run method
    @Override
    public PESDWrapper run(){
		
		// your Logic
		
		// All the templates must return a PESDWrapper obj
        return this.pesdObj;
    }
}

```

#### 2) Adding the new Template Class to the Burp extension
1. Modify PESDPanel.java by adding the a checkbox for your template

2. Modify PESDPanel.java:45 and add your template name to the String array of templates
   ```
   this.Templates = new String[]{"SAML_SSO", "OAuth2/OIDC","MY_NEW_TEMPLATE_NAME"};
   ```
   
3. Add the following lines of code to the PESDPanel constructor:
```
YOUR_TEMPLATE_checkbox.setVisible(false);
YOUR_TEMPLATE_checkbox.doClick();
```

4. In PESDPanel.java, modify *EditTemplates_ButtonActionPerformed* method by adding *your_template_checkbox.setVisible()* with false for the **if** and true for the **else** case.

5. In PESDPanel.java, fill *YOUR_TEMPLATE_checkboxActionPerformed()* method as follows
```
private void YOUR_TEMPLATE_checkboxActionPerformed(java.awt.event.ActionEvent evt) {                                                           
        if (SAML_SSO_TEMPLATE_checkbox.isSelected()){
            this.Templates[$INDEX]= "MY_NEW_TEMPLATE_NAME";
        } else {
            this.Templates[$INDEX]="";
        }
    } 
```
Note that *$INDEX* is the position of your template inside *this.Templates* array (see step 2).

6. Add the a case for the new template in TemplateRunner.java. Add it inside the switch-case in the constructor as follows:
```
case "MY_NEW_TEMPLATE_NAME":
    this.template = new NewTemplateClass(diagram, metadataObj, stdout);
    break;
```

7. When you are done with coding, name and save your template inside the templates package directory.

8. Re-build the Extension and you are ready to go. What a long journey!


## Example Template :  Flow-wide Frame Add
This simple example shows how to iterate through a PESDWrapper object and add a frame (Mermaid Alt syntax) around the entire flow being exported. This is just a demonstration of the basic iteration. 

```
/*
 * Example Template that wraps the Entire flow in a Flow Frame (Alt/end named rectangle)
 */
 
public class EmptyTemplate extends TemplateParent{
    
    public EmptyTemplate( PESDWrapper pesdObj, PrintWriter stdout) {
        super(pesdObj, stdout);
    }
	
    // put all your logic inside the run method
    @Override
    public PESDWrapper run(){
	
        pesdObj.startIterator();
        while (pesdObj.getIterator() != -1) {
            JSONObject line = pesdObj.getLine();
			
			// adding and Alt/end flow frame to wrap the entire flow
            if(pesdObj.getIterator()==0){
				pesdObj.addFlag("HELLO PESD FLOW FRAME");
			} else if (pesdObj.getIterator() == pesdObj.getSize()-1) {
				pesdObj.endAlt(pesdObj.getIterator()+1);
			}
			
            pesdObj.nextLine();
        }
        return this.pesdObj;
    }
}

```
