package burp;

import java.awt.Component;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import javax.swing.JScrollPane;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPane;
    final JTextArea beautifyTextArea = new JTextArea(5, 10);

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Anush Custom Decoder");

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        // create our UI
        SwingUtilities.invokeLater(() -> {
            //Main split pane
            mainPane = new JPanel(new BorderLayout());

            //Create the text area and scroll pane for JSON
            beautifyTextArea.setLineWrap(true);
            JPanel beautifyTextWrapper = new JPanel(new BorderLayout());
            JScrollPane beautifyScrollPane = new JScrollPane(beautifyTextArea);
            beautifyTextWrapper.add(beautifyScrollPane, BorderLayout.CENTER);
            mainPane.add(beautifyTextWrapper, BorderLayout.CENTER);
            callbacks.customizeUiComponent(mainPane);

            // Add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom beautifer tab
        return new JSONBeautifierTab(controller, editable);
    }
    @Override
    public String getTabCaption() {
        return "Decoder Pro";
    }

    @Override
    public Component getUiComponent() {
        return mainPane;
    }
    //
    // class implementing IMessageEditorTab
    //
    class JSONBeautifierTab implements IMessageEditorTab {

        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        public JSONBeautifierTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //
        @Override
        public String getTabCaption() {
            return "Decoder";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                txtInput.setText("none".getBytes());
                txtInput.setEditable(false);
            } else {
                // decodes and cleans byte array passed in
                try {
                    byte[] cleaned = decodeText(content);
                    txtInput.setText(cleaned);
                    txtInput.setEditable(editable);
                // if the message cant be decoded, it skips the url decoding and just cleans
                } catch (Exception e) {
                    String temp = new String(content);
                    temp = removeHTMLTags(temp);
                    String cleaned = applyPattern(temp);
                    txtInput.setText(cleaned.getBytes());
                }
            }
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            String json = "";
            if (txtInput.isTextModified()) {
                try {
                    IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
                    return helpers.buildHttpMessage(requestInfo.getHeaders(), json.getBytes());
                } catch (Exception e) {
                    return currentMessage;
                }
            }
            return null;
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }

        /**
         * Sends the request and response text through a url decoder 3 times
         *
         * @param content: text needed to be cleaned
         * @return Byte[]: decoded text converted into a byte array
         */
        public byte[] decodeText(byte[] content) {
            String temp = new String(content);
            String decoded = removeHTMLTags(temp);
            try {
                decoded = URLDecoder.decode(decoded, "UTF-8");
                decoded = URLDecoder.decode(decoded, "UTF-8");
                decoded = URLDecoder.decode(decoded, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return e.toString().getBytes();
            }

            String patterened = applyPattern(decoded);
            return patterened.getBytes();
        }

        /**
         * Applies hardcoded regex to string
         *
         * @param text: text needed to be regex'd
         * @return String: cleaned text
         */
        public String applyPattern(String text) {
            String pass1 = text.replaceAll("[A-Z|a-z|0-9|\\\\|\\+|//]{150,999}", "\n");
            String pass2 = pass1.replaceAll("([:|;|{|&|$])", "\n");
            return pass2;
        }

        /**
         * Regex's out the content inside a html tag
         *
         * @param text: text needed to be regex'd
         * @return String: cleaned text
         */
        public String removeHTMLTags(String text) {
            String cleaned = text.replaceAll("<[^>]*>", "");
            return cleaned;
        }
    }
}