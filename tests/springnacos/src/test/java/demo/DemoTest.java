package demo;
import com.alibaba.nacos.api.config.ConfigService;
import com.alibaba.nacos.api.config.listener.Listener;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
class DemoTest {
    @Test void configReadsInitialRemoteValueAndListenerUpdatesIt() throws Exception {
        ConfigService client=mock(ConfigService.class);
        AtomicReference<Listener> listener=new AtomicReference<>();
        when(client.getConfigAndSignListener(eq("java-demo.properties"),eq("ZC_DEMO"),eq(5000L),any())).thenAnswer(i->{listener.set(i.getArgument(3));return "greeting=version-one";});
        DynamicConfig config=new DynamicConfig(client);
        assertEquals("version-one", config.greeting());
        assertNotNull(listener.get());
        listener.get().receiveConfigInfo("greeting=version-two");
        assertEquals("version-two",config.greeting());
    }
    @Test void missingRemoteConfigFailsInsteadOfPretendingReady() throws Exception {
        assertThrows(IllegalStateException.class,()->new DynamicConfig(mock(ConfigService.class)));
    }
    @Test void httpEchoUsesCurrentConfigAndPreservesBody() throws Exception {
        DynamicConfig config=mock(DynamicConfig.class);when(config.greeting()).thenReturn("version-two");
        var mvc=MockMvcBuilders.standaloneSetup(new DemoController(config,"spring-b","",null)).build();
        mvc.perform(post("/echo").contentType("text/plain; charset=utf-8").header("X-Request-ID","unit-1").content("你好 Spring"))
            .andExpect(status().isOk()).andExpect(jsonPath("$.greeting").value("version-two"))
            .andExpect(jsonPath("$.role").value("spring-b")).andExpect(jsonPath("$.request_id").value("unit-1"))
            .andExpect(jsonPath("$.echo").value("你好 Spring"));
    }
    @Test void forwardedHttpPreservesDyeAndUnmarkedRequestsStayUnmarked() throws Exception {
        DynamicConfig config=mock(DynamicConfig.class);when(config.greeting()).thenReturn("version-one");
        var received=new AtomicReference<String>();var body=new AtomicReference<String>();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/echo",ex->{received.set(ex.getRequestHeaders().getFirst("Debug-Token"));body.set(new String(ex.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));byte[] b="{\"role\":\"spring-b\"}".getBytes(StandardCharsets.UTF_8);ex.getResponseHeaders().set("Content-Type","application/json");ex.sendResponseHeaders(200,b.length);ex.getResponseBody().write(b);ex.close();});server.start();
        try {
            var mvc=MockMvcBuilders.standaloneSetup(new DemoController(config,"spring-a","http://127.0.0.1:"+server.getAddress().getPort(),null)).build();
            mvc.perform(post("/demo").header("Debug-Token","yes").contentType("text/plain; charset=utf-8").content("payload"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.downstream.role").value("spring-b"));
            assertEquals("yes",received.get());assertEquals("payload",body.get());
            mvc.perform(post("/demo").contentType("text/plain; charset=utf-8").content("next")).andExpect(status().isOk());
            assertNull(received.get());assertEquals("next",body.get());
        } finally { server.stop(0); }
    }
    @Test void nacosEchoIncludesActualConfigReply() throws Exception {
        DynamicConfig config=mock(DynamicConfig.class);when(config.greeting()).thenReturn("version-two");
        NacosHttpQuery query=mock(NacosHttpQuery.class);when(query.query(any())).thenReturn("greeting=version-two\n");
        var mvc=MockMvcBuilders.standaloneSetup(new DemoController(config,"spring-b","",query)).build();
        mvc.perform(post("/nacos-echo").contentType("text/plain; charset=utf-8").content("body"))
            .andExpect(status().isOk()).andExpect(jsonPath("$.nacos_content").value("greeting=version-two\n"));
        verify(query).query(any());
    }
    @Test void nacosEntryUsesNacosDownstreamRoute() throws Exception {
        DynamicConfig config=mock(DynamicConfig.class);when(config.greeting()).thenReturn("version-two");
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/nacos-echo",ex->{byte[] b="{\"nacos_content\":\"from-nacos\"}".getBytes(StandardCharsets.UTF_8);ex.sendResponseHeaders(200,b.length);ex.getResponseBody().write(b);ex.close();});server.start();
        try {
            var mvc=MockMvcBuilders.standaloneSetup(new DemoController(config,"spring-a","http://127.0.0.1:"+server.getAddress().getPort(),null)).build();
            mvc.perform(post("/nacos-demo").contentType("text/plain; charset=utf-8").content("body"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.downstream.nacos_content").value("from-nacos"));
        } finally {server.stop(0);}
    }
}
