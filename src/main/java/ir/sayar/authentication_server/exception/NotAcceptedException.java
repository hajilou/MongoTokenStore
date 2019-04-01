package ir.sayar.authentication_server.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * @author meghdad hajilo
 * This class writed for handel 406 Exception
 */
@ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
public class NotAcceptedException extends RuntimeException {

    public NotAcceptedException() {
    }
    public NotAcceptedException(String message) {
        super(message);
    }
}
