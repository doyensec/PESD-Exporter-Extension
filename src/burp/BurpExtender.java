
package burp;

import java.util.List;
import pesd.PESDExportTab;

import java.util.*;
import java.awt.event.*;
import javax.swing.JMenuItem;
import pesd.PESDPanel;

public class BurpExtender implements IBurpExtender,IContextMenuFactory
{
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private final static String DOMAIN_ACTORS = "Domains as Actors";
    private final static String ENDPOINTS_ACTORS = "Endpoints as Actors";
    private final static String CLEAN_FLOW = "Clean Flow";
    private PESDExportTab Tab;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("PESD Exporter");
        PESDExportTab tab = new PESDExportTab(callbacks, helpers);
        this.Tab=tab;
        callbacks.addSuiteTab(tab);
        callbacks.registerContextMenuFactory(this);
       
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return null;
        JMenuItem i1 = new JMenuItem(DOMAIN_ACTORS);
        JMenuItem i2 = new JMenuItem(ENDPOINTS_ACTORS);
        JMenuItem i3 = new JMenuItem(CLEAN_FLOW);
        i1.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    copyMessages(messages,0);
                }
        });
        i2.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    copyMessages(messages,1);
                }
        });
        i3.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    cleanFlow();
                }
        });
        return Arrays.asList(i1,i2,i3);
    }
    
    private void copyMessages(IHttpRequestResponse[] messages, Integer opMode) {
        PESDPanel panel = (PESDPanel) this.Tab.getPanel();
        panel.setItems(messages,opMode);
        panel.setCountLabel();
        if (panel.getAutoExport()){
            panel.clickPESDExport_button();
        }
        
	}
    
    private void cleanFlow() {
        PESDPanel panel = (PESDPanel) this.Tab.getPanel();
        IHttpRequestResponse iHttpRequestResponse[] = new IHttpRequestResponse[0];
        panel.items=iHttpRequestResponse;
        panel.setCountLabel();
	}
}
