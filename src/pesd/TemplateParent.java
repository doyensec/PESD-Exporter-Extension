package pesd;

import java.io.PrintWriter;

// This is the PESD template parent class
//
// In order to write new templates to match your needs you have to create a template class which extends this one
// and overrides the run method.
//


public class TemplateParent {
    public PrintWriter stdout;
    public PESDWrapper pesdObj;
    
    public TemplateParent(PESDWrapper pesdObj, PrintWriter stdout) {
        // PESD Template required vars for the constructor
        this.stdout = stdout;
        this.pesdObj = pesdObj;
    }
    
    public PESDWrapper run(){
        //Override This
        return this.pesdObj;
    }
    
}
