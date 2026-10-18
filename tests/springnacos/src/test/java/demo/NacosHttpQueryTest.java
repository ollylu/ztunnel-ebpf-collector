package demo;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;
class NacosHttpQueryTest {
    @Test void realConfigQueryForwardsOnlyThisRequestsDyeAndReturnsReply() throws Exception {
        var dye=new AtomicReference<String>();var id=new AtomicReference<String>();var path=new AtomicReference<String>();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/nacos/v1/cs/configs",ex->{
            dye.set(ex.getRequestHeaders().getFirst("Debug-Token"));id.set(ex.getRequestHeaders().getFirst("X-Request-ID"));path.set(ex.getRequestURI().toString());
            byte[] b="greeting=version-two\n".getBytes(StandardCharsets.UTF_8);ex.sendResponseHeaders(200,b.length);ex.getResponseBody().write(b);ex.close();
        });server.start();
        try {
            var client=new NacosHttpQuery("127.0.0.1:"+server.getAddress().getPort());
            var marked=new MockHttpServletRequest();marked.addHeader("Debug-Token","yes");marked.addHeader("X-Request-ID","config-20");
            assertEquals("greeting=version-two\n",client.query(marked));assertEquals("yes",dye.get());assertEquals("config-20",id.get());
            assertEquals("/nacos/v1/cs/configs?dataId=java-demo.properties&group=ZC_DEMO",path.get());
            var plain=new MockHttpServletRequest();plain.addHeader("X-Request-ID","config-21");client.query(plain);
            assertNull(dye.get());assertEquals("config-21",id.get());
        } finally {server.stop(0);}
    }
    @Test void nacosErrorMustNotBeReturnedAsSuccessfulConfig() throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/nacos/v1/cs/configs",ex->{ex.sendResponseHeaders(404,-1);ex.close();});server.start();
        try {assertThrows(IllegalStateException.class,()->new NacosHttpQuery("127.0.0.1:"+server.getAddress().getPort()).query(new MockHttpServletRequest()));}
        finally {server.stop(0);}
    }
}
