package kr.gilmok.auth.global.util;

import jakarta.servlet.http.HttpServletRequest;

public class ClientIpUtils {

    private ClientIpUtils() {
        // 유틸리티 클래스이므로 인스턴스화 방지
    }

    public static String extract(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}
