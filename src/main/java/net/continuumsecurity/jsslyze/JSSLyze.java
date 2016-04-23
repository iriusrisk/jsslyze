package net.continuumsecurity.jsslyze;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Stephen de Vries on 23/04/2016.
 *
 * Stateful wrapper around the SSLyze python utility.  Used to run and parse the output.
 *
 */
public class JSSLyze {
    ProcessExecutor executor;
    SSLyzeParser parser;
    String outputFilename = "sslyze.output";
    String pathToSslyze;
    String output;

    public JSSLyze(String pathToSslyze) {
        this.pathToSslyze = pathToSslyze;
    }

    public JSSLyze(String pathToSslyze, String outputFilename) {
        this(pathToSslyze);
        this.outputFilename = outputFilename;
    }

    public void execute(String options, String host, int port) throws IOException {
        List<String> cmds = new ArrayList<>();
        cmds.add(pathToSslyze);
        cmds.addAll(Arrays.asList(options.split("\\s+")));
        if (port > -1) {
            host = host + ":" + port;
        }
        cmds.add(host);
        executor = new ProcessExecutor(cmds);
        executor.setFilename(outputFilename);
        executor.start();
        output = executor.getOutput();
        parser = new SSLyzeParser(output);
    }

    public SSLyzeParser getParser() {
        return parser;
    }

    public String getOutput() {
        return output;
    }

}
