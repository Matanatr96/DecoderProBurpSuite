import burp.*;

import java.awt.Component;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor cleanRequest;
    private IMessageEditor cleanResponse;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private final String[] cols = new String[]{"URL", "Length", "Method", "Status Code", "Content Type", "Mime Type", "Time"};
    private final String[] contentArray = new String[]{"N/A", "URL", "Multipart", "XML", "JSON", "AMF", "Unknown"};

    private IHttpRequestResponse currentlyDisplayedItem;
    private PrintWriter stdout;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Anush Custom logger");
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // create our UI
        SwingUtilities.invokeLater(() -> {
            // main split pane
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // table of log entries
            Table logTable = new Table(BurpExtender.this);
            JScrollPane scrollPane = new JScrollPane(logTable);
            splitPane.setLeftComponent(scrollPane);

            // tabs with request/response viewers
            JTabbedPane tabs = new JTabbedPane();
            requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            cleanRequest = callbacks.createMessageEditor(BurpExtender.this, true);
            cleanResponse = callbacks.createMessageEditor(BurpExtender.this, true);
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());
            tabs.addTab("Decoded Request", cleanRequest.getComponent());
            tabs.addTab("Decoded Response", cleanResponse.getComponent());
            splitPane.setRightComponent(tabs);

            // customize our UI components
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(logTable);
            callbacks.customizeUiComponent(scrollPane);
            callbacks.customizeUiComponent(tabs);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        return "Logger Pro";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        byte[] request = messageInfo.getRequest();
        byte[] response = messageInfo.getResponse();

        IRequestInfo reqInfo = helpers.analyzeRequest(request);
        IResponseInfo resInfo = helpers.analyzeResponse(response);
        Byte contentTypeByte = reqInfo.getContentType();
        String content = contentArray[contentTypeByte];

        // only process responses
        if (!messageIsRequest) {
            // create a new log entry with the message details
            synchronized(log) {
                int row = log.size();
                log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl(), reqInfo.getMethod(), content, resInfo.getStatusCode(), resInfo.getStatedMimeType()));
                fireTableRowsInserted(row, row);
            }
        }

        //callbacks.issueAlert(messageInfo.getRequest().toString());

        stdout.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                        messageInfo.getHttpService() +
                        " [" + callbacks.getToolName(toolFlag) + "]");
    }

    //
    // extend AbstractTableModel
    //
    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return cols.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        if (columnIndex >= cols.length) {
            return "";
        } else {
            return cols[columnIndex];
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.length;
            case 2:
                return logEntry.method;
            case 3:
                return logEntry.statusCode;
            case 4:
                return logEntry.contentType;
            case 5:
                return logEntry.mimeType;
            case 6:
                return logEntry.time;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //
    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            LogEntry logEntry = log.get(row);
            String request = new String(logEntry.requestResponse.getRequest());
            String response = new String(logEntry.requestResponse.getResponse());

            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            cleanRequest.setMessage(decodeText(request), false);
            cleanResponse.setMessage(decodeText(response), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * Sends the request and response text through a url decoder 3 times
     *
     * @param text: text needed to be cleaned
     * @return Byte[]: decoded text converted into a byte array
     */
    public byte[] decodeText(String text) {
        String decoded = removeHTMLTags(text);
        try {
            decoded = URLDecoder.decode(text, "UTF-8");
            decoded = URLDecoder.decode(decoded, "UTF-8");
            decoded = URLDecoder.decode(decoded, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
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

    //
    // class to hold details of each log entry
    //
    private static class LogEntry {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String time;
        final int length;
        final String method;
        final String contentType;
        final Short statusCode;
        final String mimeType;

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url, String method, String content, Short statusCode, String mimeType) {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.length = getLength(requestResponse.getResponse());
            this.method = method;
            this.contentType = content;
            this.statusCode = statusCode;
            this.mimeType = mimeType;

            LocalDateTime now = LocalDateTime.now();
            this.time = String.format("%s %s %02d:%02d:%02d", now.getMonth(), now.getDayOfMonth(), now.getHour(), now.getMinute(), now.getSecond());
        }

        /**
         * Regex's out the content inside a html tag
         *
         * @param text: the byte array
         * @return int: the length of the byte array passed in
         */
        public int getLength(byte[] text) {
            String temp = new String(text);
            return temp.length();
        }
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Anush was unplugged ");
    }
}
