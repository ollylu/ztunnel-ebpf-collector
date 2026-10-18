package demo;
import java.util.Properties;
import com.alibaba.nacos.api.NacosFactory;
import com.alibaba.nacos.api.config.ConfigService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args){SpringApplication.run(DemoApplication.class,args);}
    @Bean(destroyMethod="shutDown") ConfigService configService() throws Exception {
        Properties p=new Properties();p.setProperty("serverAddr",System.getenv("NACOS_ADDR"));
        return NacosFactory.createConfigService(p);
    }
    @Bean NacosHttpQuery nacosHttpQuery(){return new NacosHttpQuery(System.getenv("NACOS_ADDR"));}
    @Bean DynamicConfig dynamicConfig(ConfigService client) throws Exception{return new DynamicConfig(client);}
}
