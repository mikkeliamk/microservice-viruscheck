package fi.mamk.osa.microservices;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import net.xeoh.plugins.base.annotations.Capabilities;
import net.xeoh.plugins.base.annotations.PluginImplementation;
import com.belvain.soswe.workflow.Microservice;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

@PluginImplementation
public class VirusCheck extends Microservice {

    @Capabilities
    public String[] caps() {
        return new String[] {"name:VirusCheck"};
    }

    @Override
    public boolean execute(String input, HashMap<String, Object> options)
            throws Exception {
        boolean success = false;
        String state = "error";
        String output = "";
        String filename = "";
        String importdirectory = "";
        String uploaddirectory = "";
        String faileddirectory = "";
        String organization = "";
        String user = "";
        
        if (options != null) {
            if (options.containsKey("filename")) {
                filename = options.get("filename").toString();
            }
            if (options.containsKey("importdirectory")) {
                importdirectory = options.get("importdirectory").toString();
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
                                                         .replace("{uploaddir}", importdirectory)
                                                         .replace("{faileddir}", faileddirectory));
            p.waitFor();
            
            String line = null;
            String checkText = "Infected files:";
            String cleanText = "Infected files: 0";
            
            // read output
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(checkText)) {
                    if (line.equals(cleanText)) {
                        success = true;
                        state = "completed";
                    }
                    break;
                }
            }       
            
            /*
             * to really know if the command did what you wanted it to do you need to analyze output here and determine if
             * it is correct. Otherwise UI may display that execution succeeded for example if ping command was successful
             * but there was no answer.
             */
            
            output += "Done ClamAV's clamscan for "+filename+", returnValue:"+Boolean.toString(success)+"\n";
           
        } catch (Exception e) {
            output += "ClamAV's clamscan for "+filename+" failed.\n";
        }
        
        if (!success) {
            // if exception, move imported file to failed directory
            File file = new File(importdirectory + filename);
            File failedfile = findFileName(faileddirectory, filename);
                        
            if (!failedfile.getParentFile().exists()) {
                failedfile.getParentFile().mkdirs();
            }
            
            FileUtils.moveFile(file, failedfile);
        }
        
        super.setState(state);
        super.setOutput(output);
        super.setCompleted(true);
        
        String log = super.getLog().replace("{organization}", organization).replace("{user}", user);
        super.setLog(log);
        log();
        
        return success;
    }
    
    /**
     * findFileName
     * @param dir              absolute path 
     * @param fileName         fileName
     * @return                 filename with the running nr of copies if file already exists in dir
     */   
    private File findFileName(String dir, String fileName) {
        
        File file = new File(dir + fileName);
        if (!file.exists()) {
            return file;
        }
               
        String baseName = FilenameUtils.removeExtension(fileName);
        String extension = FilenameUtils.getExtension(fileName);

        for (int i = 1; i < Integer.MAX_VALUE; i++) {
            Path path = Paths.get(dir, String.format("%s(%d).%s", baseName, i, extension));
            if (!Files.exists(path)) {
                return path.toFile();
            }
        }
        return file;
    }
}