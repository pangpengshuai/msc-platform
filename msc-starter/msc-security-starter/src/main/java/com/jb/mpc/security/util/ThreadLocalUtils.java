package com.jb.mpc.security.util;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ThreadLocalUtils
{
  private static final ThreadLocal threadLocal = new ThreadLocal();

  public static void setObjectToThreadLocal(String key, Object value)
  {
    Map map = (Map)threadLocal.get();

    if (map == null) {
      map = new LinkedHashMap();
      threadLocal.set(map);
    }

    map.put(key, value);
  }

  public static Object getObjectFromThreadLocal(String key)
  {
    Map map = (Map)threadLocal.get();

    if (map == null) {
      return null;
    }

    return map.get(key);
  }

  public static Object removeObjectFromThreadLocal(String key)
  {
    Map map = (Map)threadLocal.get();

    if (map == null) {
      return null;
    }

    return map.remove(key);
  }
}