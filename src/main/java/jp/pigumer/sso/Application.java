package jp.pigumer.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@SpringBootApplication
@Controller
public class Application {
    
    @RequestMapping("/")
    String index(Model model) {
        model.addAttribute("hello", "/hello");
        return "index";
    }
    
    @RequestMapping("/hello")
    String hello() {
        return "hello";
    }
    
    /**
     * main
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
