package demo;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;

// Dedicated demo HTTP query; does not alter Nacos SDK background gRPC channels.
public class NacosHttpQuery {
    private final URI endpoint;
    private final HttpClient client=HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(2)).build();
    public NacosHttpQuery(String address){endpoint=URI.create("http://"+address+"/nacos/v1/cs/configs?dataId=java-demo.properties&group=ZC_DEMO");}
    public String query(HttpServletRequest request) throws Exception {
        var b=HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(3)).GET();
        for(String name:new String[]{"Debug-Token","X-Request-ID","X-Demo-Header"})
            for(String value:Collections.list(request.getHeaders(name)))b.header(name,value);
        var r=client.send(b.build(),HttpResponse.BodyHandlers.ofInputStream());
        try(var input=r.body()){
            byte[] bytes=input.readNBytes(4097);
            if(r.statusCode()!=200 || bytes.length>4096)throw new IllegalStateException("Nacos config query failed or oversized");
            return new String(bytes,StandardCharsets.UTF_8);
        }
    }
}
