package demo;
import com.alibaba.nacos.api.config.ConfigService;
import com.alibaba.nacos.api.config.listener.Listener;
import java.io.StringReader;
import java.util.Properties;
import java.util.concurrent.Executor;

// One synthetic dataId; SDK owns its bounded connection and listener lifecycle.
public class DynamicConfig {
    private volatile String greeting;
    public DynamicConfig(ConfigService client) throws Exception {
        String value=client.getConfigAndSignListener("java-demo.properties","ZC_DEMO",5000,new Listener(){
            public Executor getExecutor(){return null;}
            public void receiveConfigInfo(String value){apply(value);}
        });
        apply(value);
    }
    private void apply(String value) {
        if(value==null || value.length()>4096) throw new IllegalStateException("missing or oversized demo config");
        Properties p=new Properties();
        try {p.load(new StringReader(value));} catch(Exception e){throw new IllegalStateException("invalid demo config",e);}
        String next=p.getProperty("greeting");
        if(next==null || next.isBlank() || next.length()>128)throw new IllegalStateException("greeting required, max 128 characters");
        greeting=next;
    }
    public String greeting(){return greeting;}
}
