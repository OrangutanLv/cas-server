package org.jasig.cas.web.flow;

import org.jasig.cas.authentication.Credential;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @Title: LoginAuthenticationInterceptor
 * @Package org.jasig.cas.web.flow
 * @Description: 利用HTTP请求跳转回子系统登录页
 * @Author Walter.Lv(wlv003)
 * @Date 8/2/2019 11:45 AM
 * @Version V1.0
 */
public class LoginAuthenticationInterceptor {

    public final Boolean IS_INTERCEPT = false;

    /**
     * Logger instance.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Webflow event helper component.
     */
    private final EventFactorySupport eventFactorySupport = new EventFactorySupport();

    public Event login(final RequestContext context, Credential credential) {
        if (!IS_INTERCEPT) {
            return this.eventFactorySupport.event(this, "viewLoginForm");
        }
        // in login's webflow : we can get the value from context as it has already been stored
        String tgtId = WebUtils.getTicketGrantingTicketId(context);
        String loginTicket = WebUtils.getLoginTicketFromFlowScope(context);
        if (credential == null) {
            credential = WebUtils.getCredential(context);
        }
        logger.debug(String.format("login interceptor: tgtId: %s, loginTicket: %s, credential: %s.", tgtId, loginTicket, credential));
        // TODO 利用http请求向系统传递参数，并根据返回值判断下一步的跳转
        return this.eventFactorySupport.event(this, "submit");
    }

    public Event logout(final RequestContext context) {
        // in login's webflow : we can get the value from context as it has already been stored
        String tgtId = WebUtils.getTicketGrantingTicketId(context);
        logger.debug("logout interceptor");
        return this.eventFactorySupport.event(this, "login");
    }
}
