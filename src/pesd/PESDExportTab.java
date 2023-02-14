
package pesd;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import javax.swing.JPanel;
/**
 *
 * @author francesco lacerenza  https://twitter.com/lacerenza_fra
 */

public class PESDExportTab implements ITab {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JPanel panel;

    public PESDExportTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        JPanel panelCreate = new PESDPanel(callbacks, helpers);
        this.panel=panelCreate;
        this.panel.setMaximumSize(this.panel.getMinimumSize());
    }

    @Override
    public String getTabCaption() {
        return "PESD Exporter";
    }

    @Override
    public Component getUiComponent() {
        callbacks.customizeUiComponent(this.panel);
        return this.panel;
    }

    public JPanel getPanel() {
        return panel;
    }
}
