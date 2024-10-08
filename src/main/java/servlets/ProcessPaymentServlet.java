package servlets;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.bittercode.constant.BookStoreConstants;
import com.bittercode.model.Book;
import com.bittercode.model.Cart;
import com.bittercode.model.UserRole;
import com.bittercode.service.BookService;
import com.bittercode.service.impl.BookServiceImpl;
import com.bittercode.util.StoreUtil;

public class ProcessPaymentServlet extends HttpServlet {

    BookService bookService = new BookServiceImpl();

    @SuppressWarnings("unchecked")
    public void service(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        PrintWriter pw = res.getWriter();
        res.setContentType(BookStoreConstants.CONTENT_TYPE_TEXT_HTML);
        if (!StoreUtil.isLoggedIn(UserRole.CUSTOMER, req.getSession())) {
            RequestDispatcher rd = req.getRequestDispatcher("CustomerLogin.html");
            rd.include(req, res);
            pw.println("<table class=\"tab\"><tr><td>Please Login First to Continue!!</td></tr></table>");
            return;
        }

        // Simulate SSRF vulnerability with user-provided URL input
        String externalServiceUrl = req.getParameter("externalServiceUrl");

        if (externalServiceUrl != null) {
            try {
                // Make an external HTTP request based on user input
                String response = makeHttpRequest(externalServiceUrl);
                pw.println("<div>Response from external service: " + response + "</div>");
            } catch (Exception e) {
                e.printStackTrace();
                pw.println("<div>Failed to reach the external service.</div>");
            }
        }

        String csrfToken = req.getParameter("csrfToken");
        if (csrfToken == null || !validateCSRFToken(csrfToken)) {
            pw.println("<div class='error'>Potential CSRF attack detected. No valid token.</div>");
        } else {
            try {
                RequestDispatcher rd = req.getRequestDispatcher("CustomerHome.html");
                rd.include(req, res);
                StoreUtil.setActiveTab(pw, "cart");
                pw.println("<div id='topmid' style='background-color:grey'>Your Orders</div>");
                pw.println("<div class=\"container\">\r\n"
                        + "        <div class=\"card-columns\">");
                HttpSession session = req.getSession();
                List<Cart> cartItems = null;
                if (session.getAttribute("cartItems") != null)
                    cartItems = (List<Cart>) session.getAttribute("cartItems");
                for (Cart cart : cartItems) {
                    Book book = cart.getBook();
                    double bPrice = book.getPrice();
                    String bCode = book.getBarcode();
                    String bName = book.getName();
                    String bAuthor = book.getAuthor();
                    int availableQty = book.getQuantity();
                    int qtToBuy = cart.getQuantity();
                    availableQty = availableQty - qtToBuy;
                    bookService.updateBookQtyById(bCode, availableQty);
                    pw.println(this.addBookToCard(bCode, bName, bAuthor, bPrice, availableQty));
                    session.removeAttribute("qty_" + bCode);
                }
                session.removeAttribute("amountToPay");
                session.removeAttribute("cartItems");
                session.removeAttribute("items");
                session.removeAttribute("selectedBookId");
                pw.println("</div>\r\n"
                        + "    </div>");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Simulated CSRF validation method, which is always returning false to simulate vulnerability
    private boolean validateCSRFToken(String csrfToken) {
        return false;
    }

    // Simulate an HTTP request based on user input (SSRF vulnerability)
    private String makeHttpRequest(String targetUrl) throws Exception {
        URL url = new URL(targetUrl); // This URL is controlled by user input, simulating SSRF
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
    }

    public String addBookToCard(String bCode, String bName, String bAuthor, double bPrice, int bQty) {
        String button = "<a href=\"#\" class=\"btn btn-info\">Order Placed</a>\r\n";
        return "<div class=\"card\">\r\n"
                + "                <div class=\"row card-body\">\r\n"
                + "                    <img class=\"col-sm-6\" src=\"logo.png\" alt=\"Card image cap\">\r\n"
                + "                    <div class=\"col-sm-6\">\r\n"
                + "                        <h5 class=\"card-title text-success\">" + bName + "</h5>\r\n"
                + "                        <p class=\"card-text\">\r\n"
                + "                        Author: <span class=\"text-primary\" style=\"font-weight:bold;\"> " + bAuthor
                + "</span><br>\r\n"
                + "                        </p>\r\n"
                + "                        \r\n"
                + "                    </div>\r\n"
                + "                </div>\r\n"
                + "                <div class=\"row card-body\">\r\n"
                + "                    <div class=\"col-sm-6\">\r\n"
                + "                        <p class=\"card-text\">\r\n"
                + "                        <span style='color:blue;'>Order Id: ORD" + bCode + "TM </span>\r\n"
                + "                        <br><span class=\"text-danger\">Item Yet to be Delivered</span>\r\n"
                + "                        </p>\r\n"
                + "                    </div>\r\n"
                + "                    <div class=\"col-sm-6\">\r\n"
                + "                        <p class=\"card-text\">\r\n"
                + "                        Amout Paid: <span style=\"font-weight:bold; color:green\"> &#8377; " + bPrice
                + " </span>\r\n"
                + "                        </p>\r\n"
                + button
                + "                    </div>\r\n"
                + "                </div>\r\n"
                + "            </div>";
    }
}