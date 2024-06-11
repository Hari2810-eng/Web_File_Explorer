/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.cache;


import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Cache {
    private static final Map<String, Map<String, Boolean>> cache = new ConcurrentHashMap<>();

    public static void cachePermission(String userId, String path, boolean hasPermission) {
        cache.computeIfAbsent(userId, k -> new ConcurrentHashMap<>()).put(path, hasPermission);
    }

    public static Boolean getCachedPermission(String userId, String path) {
        return cache.getOrDefault(userId, new ConcurrentHashMap<>()).get(path);
    }

    public static void invalidateCache(String userId) {
        cache.remove(userId);
    }

    public static void invalidateAll() {
        cache.clear();
    }
}
