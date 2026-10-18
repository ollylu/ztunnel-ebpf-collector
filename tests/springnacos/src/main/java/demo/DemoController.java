package demo;
import java.util.Map;
import java.util.Collections;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import jakarta.servlet.http.HttpServletRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;
@RestController
public class DemoController {
    private final DynamicConfig config;
    private final String role, downstream;
    private final NacosHttpQuery nacos;
    private final HttpClient client=HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(2)).build();
    private final ObjectMapper json=new ObjectMapper();
    public DemoController(DynamicConfig config, @Value("${DEMO_ROLE:spring-demo}") String role, @Value("${DOWNSTREAM_URL:}") String downstream, NacosHttpQuery nacos){this.config=config;this.role=role;this.downstream=downstream;this.nacos=nacos;}
    @GetMapping("/healthz") public Map<String,Object> health(){return Map.of("ready",true,"greeting",config.greeting());}
    @PostMapping("/echo") public Map<String,Object> echo(@RequestBody String body,HttpServletRequest request){
        return Map.of("role",role,"greeting",config.greeting(),"request_id",request.getHeader("X-Request-ID")==null?"":request.getHeader("X-Request-ID"),"echo",body);
    }
    @PostMapping("/nacos-echo") public Map<String,Object> nacosEcho(@RequestBody String body,HttpServletRequest request) throws Exception {
        var result=new java.util.LinkedHashMap<String,Object>(echo(body,request));
        result.put("nacos_content",nacos.query(request));return result;
    }
    @PostMapping("/nacos-demo") public Map<String,Object> nacosDemo(@RequestBody String body,HttpServletRequest request) throws Exception {return forward(body,request,"/nacos-echo");}
    @PostMapping("/demo") public Map<String,Object> demo(@RequestBody String body,HttpServletRequest request) throws Exception {return forward(body,request,"/echo");}
    private Map<String,Object> forward(String body,HttpServletRequest request,String path) throws Exception {
        if(body.length()>8192)throw new IllegalArgumentException("demo body max 8192 characters");
        var b=HttpRequest.newBuilder(URI.create(downstream+path)).timeout(Duration.ofSeconds(3)).header("Content-Type","text/plain; charset=utf-8").POST(HttpRequest.BodyPublishers.ofString(body));
        for(String name:new String[]{"Debug-Token","X-Request-ID","X-Demo-Header"})
            for(String value:Collections.list(request.getHeaders(name)))b.header(name,value);
        var r=client.send(b.build(),HttpResponse.BodyHandlers.ofString());
        if(r.statusCode()!=200 || r.body().length()>16384)throw new IllegalStateException("downstream demo failed");
        return Map.of("role",role,"greeting",config.greeting(),"downstream",json.readValue(r.body(),Map.class));
    }
}
