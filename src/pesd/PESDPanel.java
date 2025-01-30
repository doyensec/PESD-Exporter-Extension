package pesd;

import burp.IExtensionHelpers;
import java.io.PrintWriter;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.Arrays;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author francesco
 */
public class PESDPanel extends javax.swing.JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    public IHttpRequestResponse[] items;
    private int operationMode;
    private PESDExporter pesdexporter;
    private Boolean[] Bools;
    private String[] Templates;
    private String metadata;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private String[] diagrams;
    public Boolean inverted;

    public PESDPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        initComponents();
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        IHttpRequestResponse iHttpRequestResponse[] = new IHttpRequestResponse[0];
        this.items = iHttpRequestResponse;
        this.operationMode = 0;
        // Bools index: 0=HasUrlParams, 1=HasBodyParam, 2=HasJsonParam, 3=HasXmlParam, 4=HasMultipartAttr, 5=HasAuthz, 6=Content-type, 7=CookiesSet, 8=HasCORS, 9=HasXFrameOp, 10=HasCSP, 11=HasCookies
        Boolean PramBools[] = new Boolean[]{true, true, true, true, true, true, true, true, true, false, true, true};
        this.Bools = PramBools;
        this.Templates = new String[]{"SAML_SSO", "OAuth2/OIDC"};
        this.inverted = false;
        
        repositoryLink.setText("https://github.com/doyensec/PESD-Exporter-Extension");
        repositoryLink.setForeground(Color.BLUE);
        repositoryLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
        repositoryLink.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI(repositoryLink.getText()));
                } catch (URISyntaxException | IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
        
        invertOrderButton.setToolTipText("Invert the order of the Proxy History items in the diagram. Enable if the last request is on top.");
        themeButton.setToolTipText("Setup your own Sequence Diagram theme using MermaidJS themes");
        modeOfOperation_ComboBox.setToolTipText("Select which HTTP component should be an actor: Domain OR Endpoint");
        autoExpButton.setToolTipText("Generate diagram as soon as Proxy History items are received");
        cleanafterexpButton.setToolTipText("Remove HTTP Requests from the extension after generation");
        boolsButton.setToolTipText("Set HTTP traffic booleans in the generated PESD. E.g. HasUrlParams, HasBodyParam, HasCORS etc.");
        
        if(!"false".equals(callbacks.loadExtensionSetting("autoOpt"))){
            autoExpButton.setSelected(true);
        }
        if("true".equals(callbacks.loadExtensionSetting("invertOpt"))){
            invertOrderButton.setSelected(true);
        }
        
        if(!"false".equals(callbacks.loadExtensionSetting("cleanOpt"))){
            cleanafterexpButton.setSelected(true);
        }
        
        if(!"false".equals(callbacks.loadExtensionSetting("flagsOpt"))){
            boolsButton.setSelected(true);
        }
        
        // Add ActionListener to handle toggle state
        autoExpButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (autoExpButton.isSelected()) {
                    callbacks.saveExtensionSetting("autoOpt", "true");
                } else {
                    callbacks.saveExtensionSetting("autoOpt", "false");
                }
            }
        });
        
        // Add ActionListener to handle toggle state
        invertOrderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (invertOrderButton.isSelected()) {
                    callbacks.saveExtensionSetting("invertOpt", "true");
                } else {
                    callbacks.saveExtensionSetting("invertOpt", "false");
                }
            }
        });
        
        // Add ActionListener to handle toggle state
        cleanafterexpButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (cleanafterexpButton.isSelected()) {
                    callbacks.saveExtensionSetting("cleanOpt", "true");
                } else {
                    callbacks.saveExtensionSetting("cleanOpt", "false");
                }
            }
        });
        
        // Add ActionListener to handle toggle state
        boolsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (boolsButton.isSelected()) {
                    callbacks.saveExtensionSetting("flagsOpt", "true");
                } else {
                    callbacks.saveExtensionSetting("flagsOpt", "false");
                }
            }
        });
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        ModeOfOperation = new javax.swing.ButtonGroup();
        buttonGroup1 = new javax.swing.ButtonGroup();
        PESDExport_button = new javax.swing.JButton();
        CleanFlow_button = new javax.swing.JButton();
        itemsCount_label = new javax.swing.JLabel();
        modeOfOperation_ComboBox = new javax.swing.JComboBox<>();
        jLabel2 = new javax.swing.JLabel();
        jSeparator2 = new javax.swing.JSeparator();
        jSeparator1 = new javax.swing.JSeparator();
        repositoryLink = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        autoExpButton = new javax.swing.JToggleButton();
        themeButton = new javax.swing.JButton();
        invertOrderButton = new javax.swing.JToggleButton();
        jSeparator3 = new javax.swing.JSeparator();
        jLabel4 = new javax.swing.JLabel();
        cleanafterexpButton = new javax.swing.JToggleButton();
        boolsButton = new javax.swing.JToggleButton();

        PESDExport_button.setText("Generate PESD");
        PESDExport_button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PESDExport_buttonActionPerformed(evt);
            }
        });

        CleanFlow_button.setText("Clean Flow");
        CleanFlow_button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CleanFlow_buttonActionPerformed(evt);
            }
        });

        itemsCount_label.setText("Items count : 0");

        modeOfOperation_ComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Domains as Actors", "Endpoints as Actors" }));
        modeOfOperation_ComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                modeOfOperation_ComboBoxActionPerformed(evt);
            }
        });

        jLabel2.setText("Proxy Enriched Sequence Diagrams Exporter v2.0");

        repositoryLink.setText("jLabel3");

        jLabel1.setText("More info at");

        autoExpButton.setText("Auto-Export");
        autoExpButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                autoExpButtonActionPerformed(evt);
            }
        });

        themeButton.setText("Global Diagram Theme ");
        themeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                themeButtonActionPerformed(evt);
            }
        });

        invertOrderButton.setText("Invert ProxyHistory Order");
        invertOrderButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                invertOrderButtonActionPerformed(evt);
            }
        });

        jLabel4.setText("Extension Options");

        cleanafterexpButton.setText("Clean Items After Export");
        cleanafterexpButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cleanafterexpButtonActionPerformed(evt);
            }
        });

        boolsButton.setText("HTTP Boolean Flags");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.TRAILING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGap(7, 7, 7)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(repositoryLink)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGap(40, 40, 40)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(itemsCount_label)
                                .addGap(18, 18, 18)
                                .addComponent(CleanFlow_button, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(PESDExport_button))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(1, 1, 1)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(cleanafterexpButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(modeOfOperation_ComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jLabel4)
                                    .addComponent(jSeparator3)
                                    .addComponent(themeButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(autoExpButton)
                                    .addComponent(invertOrderButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(boolsButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(jSeparator2, javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 300, Short.MAX_VALUE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addComponent(jLabel5)
                .addGap(230, 230, 230))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(itemsCount_label)
                    .addComponent(PESDExport_button)
                    .addComponent(CleanFlow_button))
                .addGap(30, 30, 30)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(modeOfOperation_ComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(themeButton)
                .addGap(18, 18, 18)
                .addComponent(invertOrderButton)
                .addGap(18, 18, 18)
                .addComponent(boolsButton)
                .addGap(18, 18, 18)
                .addComponent(cleanafterexpButton)
                .addGap(18, 18, 18)
                .addComponent(autoExpButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 93, Short.MAX_VALUE)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(repositoryLink))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void PESDExport_buttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PESDExport_buttonActionPerformed

        if((!this.inverted && "true".equals(callbacks.loadExtensionSetting("invertOpt")))){
            ArrayUtils.reverse(this.items);
            this.inverted = true;
        } else if(this.inverted && "false".equals(callbacks.loadExtensionSetting("invertOpt"))){
            ArrayUtils.reverse(this.items);
            this.inverted = false;
        }
        
        if("false".equals(callbacks.loadExtensionSetting("flagsOpt"))){
            this.Bools = new Boolean[]{false, false, false, false, false, false, false, false, false, false, false, false};
        } else {
            this.Bools = new Boolean[]{true, true, true, true, true, true, true, true, true, false, true, true};
        }
    
        this.pesdexporter = new PESDExporter(callbacks, helpers, this.items, stdout, stderr, this.operationMode, this.Bools, this.Templates);
        this.diagrams = pesdexporter.generatePESD();
        this.metadata = pesdexporter.getMetadata();

        try {
            InputStream page = getClass().getResourceAsStream("/export.html");
            String response = new String(page.readAllBytes(), StandardCharsets.UTF_8);
            String[] lines = this.diagrams[0].split("\r\n|\r|\n");
            if (lines.length > 100) {
                response = response.replace("TEMPLATEINSERT1", "sequenceDiagram\n"
                        + "PESD->>User: Hey!\n"
                        + "PESD->>User: If it has more than 50 entries \n"
                        + "PESD->>User: It is not a flow\n"
                        + "PESD->>User: It is traffic history!\n"
                        + "Note right of Browser : Seriously\n"
                        + "PESD->>User: Try again with less than 50 items");
                response = response.replace("TEMPLATEINSERT2", "{}");
                response = response.replace("TEMPLATEINSERT3", "sequenceDiagram\n"
                        + "PESD->>User: Nothing to mask here!\n"
                        + "PESD->>User: Flows longer than 50 items are not supported for your own good\n"
                        + "PESD->>User: Nothing personal\n"
                        + "PESD->>User: That's it \n"
                        + "Note right of Browser : Seriously");
                response = response.replace("TEMPLATEINSERT4", callbacks.loadExtensionSetting("theme"));
            } else {
                response = response.replace("TEMPLATEINSERT1", this.diagrams[0].replace("`", "&#x60;"));
                response = response.replace("TEMPLATEINSERT2", this.metadata.replace("`", "&#x60;").replace("$","\\$"));
                response = response.replace("TEMPLATEINSERT3", this.diagrams[1].replace("`", "&#x60;"));
                response = response.replace("TEMPLATEINSERT4", callbacks.loadExtensionSetting("theme"));
            }

            File temp = File.createTempFile("exports", ".html");
            String path = temp.getAbsolutePath();
            try {
                Files.writeString(temp.toPath(), response, StandardCharsets.UTF_8);
                // directing the user to the Browser Export Page File
                Desktop.getDesktop().open(new File(path));
            } catch (Exception e) {
                stdout.println(e);
            }
        } catch (Exception e) {
            stdout.println(e);
        }

        // delete current items sent to the extension and set counter to 0 in the UI
        if("true".equals(callbacks.loadExtensionSetting("cleanOpt"))){
            IHttpRequestResponse iHttpRequestResponse[] = new IHttpRequestResponse[0];
            this.items = iHttpRequestResponse;
            setCountLabel();
        }
    }//GEN-LAST:event_PESDExport_buttonActionPerformed

    private void CleanFlow_buttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CleanFlow_buttonActionPerformed
        // delete current items sent to the extension and set counter to 0 in the UI

        IHttpRequestResponse iHttpRequestResponse[] = new IHttpRequestResponse[0];
        this.items = iHttpRequestResponse;
        setCountLabel();
    }//GEN-LAST:event_CleanFlow_buttonActionPerformed


    private void modeOfOperation_ComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_modeOfOperation_ComboBoxActionPerformed

        if (this.modeOfOperation_ComboBox.getSelectedItem().toString() == "Domains as Actors") {
            this.operationMode = 0;
        } else {
            this.operationMode = 1;
        }
    }//GEN-LAST:event_modeOfOperation_ComboBoxActionPerformed

    private void autoExpButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_autoExpButtonActionPerformed
      
    }//GEN-LAST:event_autoExpButtonActionPerformed

    private void themeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_themeButtonActionPerformed
        
        String deftheme = "%%{init: {'theme': 'base', 'themeVariables': {'actorBorder':'#808486','actorTextColor':'#34343b','primaryColor': '#fa9b35','noteBkgColor':'#3f4647','noteTextColor':'#FFFFFF','noteBorderColor':'#393e3e'}}}%%";
        JTextField themeField = new JTextField();
        
        String themestr = callbacks.loadExtensionSetting("theme");
        if (themestr == null) {
            themeField.setText(deftheme);
        } else {
            themeField.setText(themestr);
        }
        
        JLabel mermaidDocs = new JLabel();
        mermaidDocs.setText("Mermaid JS Theme Docs");
        mermaidDocs.setForeground(Color.BLUE);
        mermaidDocs.setCursor(new Cursor(Cursor.HAND_CURSOR));
        mermaidDocs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI("https://mermaid.js.org/config/theming.html?#theme-variables"));
                } catch (URISyntaxException | IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
        
        Object[] msg = new Object[]{
                mermaidDocs, themeField
        };

        int confirm = JOptionPane.showConfirmDialog(this, msg, "Theme Settings", JOptionPane.OK_CANCEL_OPTION);
        if (confirm != JOptionPane.OK_OPTION) {
            return;
        }

        /*save Settings*/

        if (themeField.getText().length() > 4 &&themeField.getText().startsWith("%%") && themeField.getText().endsWith("%%")) {
            callbacks.saveExtensionSetting("theme", themeField.getText());
        } else {
            JOptionPane.showMessageDialog(this, "MermaidJS Themes start and end with %%. Setting default PESD theme.", "Invalid Theme", JOptionPane.WARNING_MESSAGE);
            callbacks.saveExtensionSetting("theme", deftheme);
        }

    // TODO add your handling code here:
    }//GEN-LAST:event_themeButtonActionPerformed

    private void invertOrderButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_invertOrderButtonActionPerformed

    }//GEN-LAST:event_invertOrderButtonActionPerformed

    private void cleanafterexpButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cleanafterexpButtonActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_cleanafterexpButtonActionPerformed

    public int setItems(IHttpRequestResponse[] newItems, Integer opMode) {
        // called from BurpExtender.java to set selected items and operation mode in the panel
        if(this.inverted){
            ArrayUtils.reverse(this.items);
        }
        
        try {
            int aLen = this.items.length;
            int bLen = newItems.length;

            // merging new selected items with previously selected items  
            IHttpRequestResponse[] c = Arrays.copyOf(this.items, aLen + bLen);
            System.arraycopy(this.items, 0, c, 0, aLen);
            System.arraycopy(newItems, 0, c, aLen, bLen);
            this.items = c;
            //updating Mode Of Operation combobox and op. mode attribute
            this.modeOfOperation_ComboBox.setSelectedIndex(opMode);
        } catch (Exception e) {
            return 0;
        }
        return 1;
    }

    public void setCountLabel() {
        itemsCount_label.setText("Items count : " + this.items.length);
        this.inverted = false;
    }

    public Boolean getAutoExport() {
        if(!"false".equals(callbacks.loadExtensionSetting("autoOpt"))){
            return true;
        } else {
            return false;
        }
    }

    public void clickPESDExport_button() {
        this.PESDExport_button.doClick();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton CleanFlow_button;
    private javax.swing.ButtonGroup ModeOfOperation;
    private javax.swing.JButton PESDExport_button;
    private javax.swing.JToggleButton autoExpButton;
    private javax.swing.JToggleButton boolsButton;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JToggleButton cleanafterexpButton;
    private javax.swing.JToggleButton invertOrderButton;
    private javax.swing.JLabel itemsCount_label;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JComboBox<String> modeOfOperation_ComboBox;
    private javax.swing.JLabel repositoryLink;
    private javax.swing.JButton themeButton;
    // End of variables declaration//GEN-END:variables


}
