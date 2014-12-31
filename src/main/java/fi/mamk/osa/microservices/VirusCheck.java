package fi.mamk.osa.microservices;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;

import net.xeoh.plugins.base.annotations.Capabilities;
import net.xeoh.plugins.base.annotations.PluginImplementation;
import com.belvain.soswe.workflow.Microservice;

@PluginImplementation
public class VirusCheck extends Microservice {

    @Capabilities
    public String[] caps() {
        return new String[] {"name:VirusCheck"};
    }

    @Override
    public boolean execute(String input, HashMap<String, Object> options) throws Exception {
        boolean success = false;
        String output = "";
        String filename = "";
        String uploaddirectory = "";
        String faileddirectory = "";
        String organization = "";
        String user = "";
        
        if (options != null) {
            if (options.containsKey("filename")) {
                filename = options.get("filename").toString();
            }
            if (options.containsKey("uploaddirectory")) {
                uploaddirectory = options.get("uploaddirectory").toString();
            }
            if (options.containsKey("faileddirectory")) {
                faileddirectory = options.get("faileddirectory").toString();
            }
            if (options.containsKey("organization")) {
                organization = options.get("organization").toString();
            }
            if (options.containsKey("username")) {
                user = options.get("username").toString();
            }
        }

        if (input != null && !input.isEmpty()) {
            //Handle input from previous microservice here
        }
        
        Process p;
        try {
            
            p = Runtime.getRuntime().exec(super.getExec().replace("{filename}", filename)
                                                         .replace("{uploaddir}", uploaddirectory)
                                                         .replace("{faileddir}", faileddirectory));
            p.waitFor();
            
            String line = null;
            String checkText = "Infected files:";
            String cleanText = "Infected files: 0";
            
            // read output
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = reader.readLine()) != null) {
                output += line+"\n";
                
                if (line.startsWith(checkText)) {
                    if (line.equals(cleanText)) {
                        success = true;
                    } else {
                        success = false;
                    }
                }
            }       
            
            /*
             * to really know if the command did what you wanted it to do you need to analyze output here and determine if
             * it is correct. Otherwise UI may display that execution succeeded for example if ping command was successful
             * but there was no answer.
             */
            
            output += "Done ClamAV's clamscan for "+filename+", returnValue:"+Boolean.toString(success)+"\n";
            
            super.setState("completed");
            super.setOutput(output);
            super.setCompleted(true);
            
        } catch (Exception e) {
            e.printStackTrace();
            success = false;
            super.setOutput(e.toString());
            super.setState("error");
            super.setCompleted(true);
            
        }

        String log = super.getLog().replace("{organization}", organization).replace("{user}", user);
        super.setLog(log);
        log();
        return success;
    }
}