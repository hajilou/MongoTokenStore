package ir.sayar.authentication_server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Meghdad Hajilo
 */

public class Print {
    private static com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();

    private static String writeObject(Object object) throws JsonProcessingException {
        return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(object);
    }

    public static void print(Object object) {
        try {
            System.out.println(
                    "\u001B[33m \nVVVVVVVVVVV " + (object == null ? "null object" : object.getClass()) + " VVVVVVVVVVV\n" +
                            object == null ? "null object" : Print.writeObject(object) +
                            "\nAAAAAAAAAAA " + (object == null ? "null object" : object.getClass()) + " AAAAAAAAAAA\n \u001B[0m");
        } catch (Exception e) {
            System.out.println("cannot write object ");
            System.out.println("AAAAAAAAAAA " + "?????" + " AAAAAAAAAAA\n");
        }
    }

    public static void print(Object subject, Object body) {
        try {
            System.out.println(
                    "\u001B[33m \nVVVVVVVVVVV " + subject + " VVVVVVVVVVV\n" +
                            body == null ? "null object" : Print.writeObject(body) +
                            "\nAAAAAAAAAAA " + subject + " AAAAAAAAAAA\n \u001B[0m");
        } catch (Exception e) {
            System.out.println("cannot write object ");
            System.out.println("AAAAAAAAAAA " + subject + " AAAAAAAAAAA\n");
        }
    }

    public static String toString(Object body) {
        try {
            return objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
