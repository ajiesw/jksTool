package com.kuer.utils;

import java.util.Date;

/**
 * DateUtil
 *
 * @author wangkj
 * @date 2022/3/1 15:59
 */
public class DateUtil {
    /**
     * 返回当前时间之后的时间
     * @param hoursInFuture
     * @return
     */
    public static Date calculateDate(int hoursInFuture) {
        long secondsNow = System.currentTimeMillis() / 1000;
        return new Date((secondsNow + ((long) hoursInFuture * 60 * 60)) * 1000);
    }
}
