package com.acme.target;

import com.acme.target.Models.User;
import jakarta.enterprise.context.RequestScoped;

/** 当前请求的登录用户,由 {@link AuthFilter} 填充。 */
@RequestScoped
public class CurrentUser {
    private User user;

    public User get() {
        return user;
    }

    public void set(User user) {
        this.user = user;
    }
}
