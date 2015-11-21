package jp.pigumer.sso;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@SpringBootApplication
@Controller
public class Application {
    
    @RequestMapping("/")
    String index(Model model) {
        model.addAttribute("hello", "/hello");
        return "index";
    }
    
    /**
     * /hello.
     * 
     * @param user User
     * @param model Model
     * @return hello
     */
    @RequestMapping("/hello")
    String hello(@CurrentUser User user, Model model) {
        model.addAttribute("user", user.getUsername());
        return "hello";
    }
    
    @Autowired
    private MetadataManager metadata;

    @RequestMapping(value = "/saml/idpSelection", method = RequestMethod.GET)
    public String idpSelection(HttpServletRequest request, Model model) {
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
            return "redirect:/landing";
        } else {
            Set<String> idps = metadata.getIDPEntityNames();
            model.addAttribute("idps", idps);
            return "saml/idpselection";
        }
    }
        
    /**
     * main
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
