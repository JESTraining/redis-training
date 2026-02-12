# 📚 Complete Redis Course
## From Fundamentals to Advanced Production Patterns (C# Edition)

---

## 📋 Table of Contents

1. **Fundamentals and Essential Concepts**
2. **Data Structures in Depth**
3. **Eviction Policies and Memory Strategies**
4. **Use Cases and Design Patterns**
5. **Redis Streams - Special Topic**
6. **High Availability and Scalability**
7. **Monitoring and Best Practices**

---

# MODULE 1: FUNDAMENTALS AND ESSENTIAL CONCEPTS

## 1.1 What is Redis?

Redis (REmote DIctionary Server) is an in-memory data structure store, open source, used as database, cache, and message broker.

**Key Characteristics:**
- ✅ In-memory (optional persistence)
- ✅ Rich data structures
- ✅ Atomic operations
- ✅ Single-threaded (for commands)
- ✅ Sub-millisecond latency

## 1.2 Setting Up Redis with C#

### Installation
```bash
# Install StackExchange.Redis (most popular Redis client for .NET)
dotnet add package StackExchange.Redis
```

### Basic Connection
```csharp
using StackExchange.Redis;

public class RedisService
{
    private readonly ConnectionMultiplexer _redis;
    private readonly IDatabase _db;
    
    public RedisService(string connectionString = "localhost:6379")
    {
        _redis = ConnectionMultiplexer.Connect(connectionString);
        _db = _redis.GetDatabase();
    }
    
    // Basic operations
    public async Task SetStringAsync(string key, string value, TimeSpan? expiry = null)
    {
        await _db.StringSetAsync(key, value, expiry);
    }
    
    public async Task<string?> GetStringAsync(string key)
    {
        return await _db.StringGetAsync(key);
    }
}
```

## 1.3 Key Concepts

### **Key-Value Store**
```csharp
// SET user:1000:name "John Doe"
await db.StringSetAsync("user:1000:name", "John Doe");

// GET user:1000:name
var name = await db.StringGetAsync("user:1000:name");
// Result: "John Doe"
```

### **TTL (Time To Live)**
```csharp
// SET session:token123 "user_data" EX 3600
await db.StringSetAsync("session:token123", "user_data", TimeSpan.FromSeconds(3600));

// TTL session:token123
var ttl = await db.KeyTimeToLiveAsync("session:token123");
// 3599 seconds remaining
```

### **Namespacing (convention)**
```
format: entity:id:field
example: user:1000:email
```

---

# MODULE 2: DATA STRUCTURES IN DEPTH

## 2.1 Strings
```csharp
public class RedisStringOperations
{
    private readonly IDatabase _db;
    
    public RedisStringOperations(IDatabase db)
    {
        _db = db;
    }
    
    // Basic operations
    public async Task CounterExample()
    {
        // SET counter 10
        await _db.StringSetAsync("counter", 10);
        
        // INCR counter
        var incremented = await _db.StringIncrementAsync("counter"); // 11
        
        // INCRBY counter 5
        var incrementedBy = await _db.StringIncrementAsync("counter", 5); // 16
        
        // DECR counter
        var decremented = await _db.StringDecrementAsync("counter"); // 15
    }
    
    // Batch operations
    public async Task BatchOperations()
    {
        var batch = _db.CreateBatch();
        
        var task1 = batch.StringSetAsync("key1", "value1");
        var task2 = batch.StringSetAsync("key2", "value2");
        
        batch.Execute();
        await Task.WhenAll(task1, task2);
        
        // MGET
        var keys = new RedisKey[] { "key1", "key2" };
        var values = await _db.StringGetAsync(keys);
    }
}
```

## 2.2 Hashes (Ideal for objects)
```csharp
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public int Age { get; set; }
    public string City { get; set; }
}

public class RedisHashOperations
{
    private readonly IDatabase _db;
    
    public RedisHashOperations(IDatabase db)
    {
        _db = db;
    }
    
    public async Task HashSetExample()
    {
        var user = new User { Id = 1000, Name = "Anna", Age = 30, City = "Madrid" };
        var hashKey = $"user:{user.Id}";
        
        // HSET user:1000 name "Anna" age 30 city "Madrid"
        var entries = new HashEntry[]
        {
            new HashEntry("name", user.Name),
            new HashEntry("age", user.Age),
            new HashEntry("city", user.City)
        };
        
        await _db.HashSetAsync(hashKey, entries);
        
        // HGET user:1000 name
        var name = await _db.HashGetAsync(hashKey, "name"); // "Anna"
        
        // HGETALL
        var allFields = await _db.HashGetAllAsync(hashKey);
        var retrievedUser = new User
        {
            Name = allFields.First(x => x.Name == "name").Value,
            Age = (int)allFields.First(x => x.Name == "age").Value,
            City = allFields.First(x => x.Name == "city").Value
        };
        
        // HINCRBY user:1000 age 1
        await _db.HashIncrementAsync(hashKey, "age", 1);
    }
}
```

## 2.3 Lists (FIFO/LIFO Queues)
```csharp
public class RedisListOperations
{
    private readonly IDatabase _db;
    
    public RedisListOperations(IDatabase db)
    {
        _db = db;
    }
    
    public async Task QueueExample()
    {
        // FIFO Queue (Producer-Consumer)
        // LPUSH tasks "process_payment_123"
        await _db.ListLeftPushAsync("tasks", "process_payment_123");
        
        // RPUSH tasks "send_email_456"
        await _db.ListRightPushAsync("tasks", "send_email_456");
        
        // LPOP tasks
        var task = await _db.ListLeftPopAsync("tasks"); // "process_payment_123"
        
        // Get all items
        var allTasks = await _db.ListRangeAsync("tasks");
    }
    
    public async Task StackExample()
    {
        // LIFO Stack
        await _db.ListLeftPushAsync("stack", "element1");
        await _db.ListLeftPushAsync("stack", "element2");
        var popped = await _db.ListLeftPopAsync("stack"); // "element2"
    }
}
```

## 2.4 Sets (Unique values, unordered)
```csharp
public class RedisSetOperations
{
    private readonly IDatabase _db;
    
    public RedisSetOperations(IDatabase db)
    {
        _db = db;
    }
    
    public async Task SetExamples()
    {
        // SADD active:users "user1" "user2" "user3"
        await _db.SetAddAsync("active:users", "user1");
        await _db.SetAddAsync("active:users", "user2");
        await _db.SetAddAsync("active:users", "user3");
        
        // SISMEMBER active:users "user1"
        var isMember = await _db.SetContainsAsync("active:users", "user1"); // true
        
        // SMEMBERS
        var members = await _db.SetMembersAsync("active:users");
        
        // SINTER group1 group2
        var group1 = new RedisKey[] { "group1", "group2" };
        var intersection = await _db.SetCombineAsync(SetOperation.Intersect, group1);
    }
}
```

## 2.5 Sorted Sets (With scores)
```csharp
public class RedisSortedSetOperations
{
    private readonly IDatabase _db;
    
    public RedisSortedSetOperations(IDatabase db)
    {
        _db = db;
    }
    
    public async Task SortedSetExamples()
    {
        // ZADD leaderboard 1000 "player1" 850 "player2" 1200 "player3"
        await _db.SortedSetAddAsync("leaderboard", "player1", 1000);
        await _db.SortedSetAddAsync("leaderboard", "player2", 850);
        await _db.SortedSetAddAsync("leaderboard", "player3", 1200);
        
        // ZREVRANGE leaderboard 0 2 WITHSCORES - Top 3
        var topPlayers = await _db.SortedSetRangeByRankWithScoresAsync(
            "leaderboard", 0, 2, Order.Descending);
        
        foreach (var player in topPlayers)
        {
            Console.WriteLine($"{player.Element}: {player.Score}");
        }
        
        // ZSCORE leaderboard "player1"
        var score = await _db.SortedSetScoreAsync("leaderboard", "player1");
    }
}
```

---

# MODULE 3: EVICTION POLICIES AND MEMORY STRATEGIES

## 3.1 Eviction Concept

Redis is in-memory → when memory fills up, eviction policies are activated to free space by removing keys.

## 3.2 Eviction Policies (maxmemory-policy)

| Policy | Description | Use Case |
|--------|-------------|----------|
| **noeviction** | Doesn't remove anything, returns error on writes | Critical cache that must not be lost |
| **allkeys-lru** | Removes least recently used keys from ALL | General cache (recommended) |
| **volatile-lru** | Removes only keys with TTL, LRU among them | Mixed cache (fixed data + expirable) |
| **allkeys-lfu** | Removes least frequently used | Consistent access patterns |
| **volatile-lfu** | LFU only on keys with TTL | Similar to volatile-lru |
| **allkeys-random** | Removes randomly | Uniform data access |
| **volatile-random** | Random only on keys with TTL | Specific cases |
| **volatile-ttl** | Removes keys with shortest TTL | Urgent temporary data |

## 3.3 Configuration and Monitoring in C#

```csharp
public class RedisMemoryMonitor
{
    private readonly IDatabase _db;
    private readonly IServer _server;
    
    public RedisMemoryMonitor(ConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
        _server = redis.GetServer(redis.GetEndPoints().First());
    }
    
    public async Task<MemoryInfo> GetMemoryInfoAsync()
    {
        var info = await _server.InfoAsync("memory");
        var memorySection = info.FirstOrDefault(x => x.Key == "memory");
        
        return new MemoryInfo
        {
            UsedMemory = memorySection?.FirstOrDefault(x => x.Key == "used_memory").Value,
            MaxMemory = memorySection?.FirstOrDefault(x => x.Key == "maxmemory").Value,
            EvictedKeys = memorySection?.FirstOrDefault(x => x.Key == "evicted_keys").Value,
            Policy = memorySection?.FirstOrDefault(x => x.Key == "maxmemory_policy").Value
        };
    }
    
    public async Task<long> GetMemoryUsageAsync(string key)
    {
        // MEMORY USAGE my_key
        var result = await _db.ExecuteAsync("MEMORY", "USAGE", key);
        return (long)result;
    }
}

public class MemoryInfo
{
    public string UsedMemory { get; set; }
    public string MaxMemory { get; set; }
    public string EvictedKeys { get; set; }
    public string Policy { get; set; }
}
```

---

# MODULE 4: USE CASES AND DESIGN PATTERNS

## 4.1 PATTERN: Cache-Aside (Lazy Loading)

**Purpose:** Reduce load on primary database

```csharp
public class UserService
{
    private readonly IDatabase _cache;
    private readonly DbContext _dbContext;
    private readonly ILogger<UserService> _logger;
    
    public UserService(ConnectionMultiplexer redis, DbContext dbContext, ILogger<UserService> logger)
    {
        _cache = redis.GetDatabase();
        _dbContext = dbContext;
        _logger = logger;
    }
    
    public async Task<User> GetUserAsync(int userId)
    {
        var cacheKey = $"user:{userId}";
        
        try
        {
            // 1. Try to get from cache
            var cachedUser = await _cache.StringGetAsync(cacheKey);
            
            if (!cachedUser.IsNull)
            {
                _logger.LogInformation("Cache hit for user {UserId}", userId);
                return JsonSerializer.Deserialize<User>(cachedUser!);
            }
            
            _logger.LogInformation("Cache miss for user {UserId}", userId);
            
            // 2. Cache miss - get from database
            var user = await _dbContext.Users.FindAsync(userId);
            
            if (user != null)
            {
                // 3. Store in cache with TTL
                var serialized = JsonSerializer.Serialize(user);
                await _cache.StringSetAsync(cacheKey, serialized, TimeSpan.FromHours(1));
            }
            
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user {UserId}", userId);
            // Fallback to database directly
            return await _dbContext.Users.FindAsync(userId);
        }
    }
    
    public async Task UpdateUserAsync(User user)
    {
        // Write-Through pattern
        var cacheKey = $"user:{user.Id}";
        
        // Update database first
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        // Update cache
        var serialized = JsonSerializer.Serialize(user);
        await _cache.StringSetAsync(cacheKey, serialized, TimeSpan.FromHours(1));
        
        // Alternative: Invalidate cache
        // await _cache.KeyDeleteAsync(cacheKey);
    }
}
```

## 4.2 PATTERN: Distributed Locks

**Purpose:** Coordination between multiple instances/servers

### Simple Implementation (SET NX + EX)
```csharp
public class DistributedLock : IAsyncDisposable
{
    private readonly IDatabase _redis;
    private readonly string _lockKey;
    private readonly string _lockValue;
    private readonly TimeSpan _expiry;
    private bool _isLocked;
    
    public DistributedLock(IDatabase redis, string lockName, TimeSpan expiry)
    {
        _redis = redis;
        _lockKey = $"lock:{lockName}";
        _lockValue = Guid.NewGuid().ToString();
        _expiry = expiry;
    }
    
    public static async Task<DistributedLock?> AcquireAsync(
        IDatabase redis, 
        string lockName, 
        TimeSpan expiry, 
        TimeSpan acquireTimeout)
    {
        var distributedLock = new DistributedLock(redis, lockName, expiry);
        var endTime = DateTime.UtcNow + acquireTimeout;
        
        while (DateTime.UtcNow < endTime)
        {
            if (await distributedLock.TryAcquireAsync())
            {
                return distributedLock;
            }
            
            await Task.Delay(10); // 10ms delay between attempts
        }
        
        return null;
    }
    
    private async Task<bool> TryAcquireAsync()
    {
        _isLocked = await _redis.StringSetAsync(
            _lockKey, 
            _lockValue, 
            _expiry, 
            When.NotExists
        );
        
        return _isLocked;
    }
    
    public async Task ReleaseAsync()
    {
        if (!_isLocked) return;
        
        // Lua script for atomic release
        var script = @"
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end";
        
        await _redis.ScriptEvaluateAsync(
            script,
            new RedisKey[] { _lockKey },
            new RedisValue[] { _lockValue }
        );
        
        _isLocked = false;
    }
    
    public async ValueTask DisposeAsync()
    {
        await ReleaseAsync();
    }
}

// Usage example
public class OrderProcessor
{
    private readonly IDatabase _redis;
    
    public OrderProcessor(ConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }
    
    public async Task ProcessOrderAsync(int orderId)
    {
        await using var lock_ = await DistributedLock.AcquireAsync(
            _redis,
            $"order:{orderId}",
            TimeSpan.FromSeconds(30),
            TimeSpan.FromSeconds(10)
        );
        
        if (lock_ == null)
        {
            throw new Exception("Could not acquire lock for order processing");
        }
        
        // Critical section - only one instance can execute this at a time
        await ProcessOrderInternalAsync(orderId);
    }
}
```

### Advanced Pattern: Redlock (Redis Algorithm)
```csharp
public class RedLock : IAsyncDisposable
{
    private readonly List<IDatabase> _redisNodes;
    private readonly int _quorum;
    private readonly string _resource;
    private readonly string _value;
    private readonly TimeSpan _ttl;
    private bool _acquired;
    
    public RedLock(IEnumerable<ConnectionMultiplexer> redisConnections, string resource, TimeSpan ttl)
    {
        _redisNodes = redisConnections.Select(c => c.GetDatabase()).ToList();
        _quorum = (_redisNodes.Count / 2) + 1;
        _resource = resource;
        _value = Guid.NewGuid().ToString();
        _ttl = ttl;
    }
    
    public static async Task<RedLock?> AcquireLockAsync(
        IEnumerable<ConnectionMultiplexer> redisConnections,
        string resource,
        TimeSpan ttl,
        TimeSpan acquireTimeout)
    {
        var redLock = new RedLock(redisConnections, resource, ttl);
        var startTime = DateTime.UtcNow;
        
        if (await redLock.TryAcquireAsync())
        {
            var elapsed = DateTime.UtcNow - startTime;
            
            if (elapsed < ttl)
            {
                return redLock;
            }
            
            await redLock.ReleaseAsync();
        }
        
        return null;
    }
    
    private async Task<bool> TryAcquireAsync()
    {
        var acquired = 0;
        var tasks = _redisNodes.Select(node => 
            node.StringSetAsync(_resource, _value, _ttl, When.NotExists));
        
        var results = await Task.WhenAll(tasks);
        acquired = results.Count(r => r);
        
        _acquired = acquired >= _quorum;
        return _acquired;
    }
    
    public async Task ReleaseAsync()
    {
        if (!_acquired) return;
        
        var script = @"
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end";
        
        var tasks = _redisNodes.Select(node =>
            node.ScriptEvaluateAsync(script, new RedisKey[] { _resource }, new RedisValue[] { _value }));
        
        await Task.WhenAll(tasks);
        _acquired = false;
    }
    
    public async ValueTask DisposeAsync()
    {
        await ReleaseAsync();
    }
}
```

## 4.3 PATTERN: Idempotency Keys

**Purpose:** Prevent duplicate processing of non-idempotent operations

```csharp
public class IdempotencyService
{
    private readonly IDatabase _redis;
    private readonly ILogger<IdempotencyService> _logger;
    
    public IdempotencyService(ConnectionMultiplexer redis, ILogger<IdempotencyService> logger)
    {
        _redis = redis.GetDatabase();
        _logger = logger;
    }
    
    public async Task<T> ProcessIdempotentAsync<T>(
        string idempotencyKey,
        Func<Task<T>> operation,
        TimeSpan? ttl = null)
    {
        var redisKey = $"idempotency:{idempotencyKey}";
        ttl ??= TimeSpan.FromHours(24);
        
        // Check if already processed
        var existing = await _redis.StringGetAsync(redisKey);
        if (!existing.IsNull)
        {
            _logger.LogInformation("Idempotency key {Key} already processed", idempotencyKey);
            return JsonSerializer.Deserialize<T>(existing!);
        }
        
        // Mark as processing with short TTL to prevent race conditions
        var processingMarker = await _redis.StringSetAsync(
            redisKey,
            "processing",
            TimeSpan.FromMinutes(1),
            When.NotExists
        );
        
        if (!processingMarker)
        {
            _logger.LogWarning("Idempotency key {Key} is being processed by another request", idempotencyKey);
            throw new IdempotencyKeyConflictException("Operation is already being processed");
        }
        
        try
        {
            // Execute the actual operation
            var result = await operation();
            
            // Store successful result
            var serialized = JsonSerializer.Serialize(result);
            await _redis.StringSetAsync(redisKey, serialized, ttl);
            
            return result;
        }
        catch (Exception)
        {
            // Release the key on failure
            await _redis.KeyDeleteAsync(redisKey);
            throw;
        }
    }
    
    public async Task<T?> GetPreviousResultAsync<T>(string idempotencyKey)
    {
        var redisKey = $"idempotency:{idempotencyKey}";
        var result = await _redis.StringGetAsync(redisKey);
        
        if (result.IsNull || result == "processing")
            return default;
            
        return JsonSerializer.Deserialize<T>(result!);
    }
}

public class IdempotencyKeyConflictException : Exception
{
    public IdempotencyKeyConflictException(string message) : base(message) { }
}

// Usage example in ASP.NET Core controller
[ApiController]
[Route("api/payments")]
public class PaymentsController : ControllerBase
{
    private readonly IdempotencyService _idempotencyService;
    private readonly PaymentService _paymentService;
    
    public PaymentsController(IdempotencyService idempotencyService, PaymentService paymentService)
    {
        _idempotencyService = idempotencyService;
        _paymentService = paymentService;
    }
    
    [HttpPost]
    public async Task<IActionResult> ProcessPayment(
        [FromBody] PaymentRequest request,
        [FromHeader(Name = "Idempotency-Key")] string idempotencyKey)
    {
        if (string.IsNullOrEmpty(idempotencyKey))
            return BadRequest("Idempotency-Key header is required");
        
        try
        {
            var result = await _idempotencyService.ProcessIdempotentAsync(
                idempotencyKey,
                async () => await _paymentService.ProcessPaymentAsync(request)
            );
            
            return Ok(result);
        }
        catch (IdempotencyKeyConflictException)
        {
            return Conflict("Operation is already being processed");
        }
    }
}
```

## 4.4 PATTERN: Rate Limiting

**Purpose:** Control request frequency

### Token Bucket Algorithm
```csharp
public class TokenBucketRateLimiter
{
    private readonly IDatabase _redis;
    
    public TokenBucketRateLimiter(ConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }
    
    public async Task<bool> AllowRequestAsync(
        string userId, 
        int maxTokens = 100, 
        int refillRate = 10) // tokens per second
    {
        var key = $"rate_limit:{userId}";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        var script = @"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local max_tokens = tonumber(ARGV[2])
            local refill_rate = tonumber(ARGV[3])
            
            -- Get current state
            local bucket = redis.call('hmget', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or max_tokens
            local last_refill = tonumber(bucket[2]) or now
            
            -- Refill tokens based on elapsed time
            local elapsed = now - last_refill
            tokens = math.min(max_tokens, tokens + (elapsed * refill_rate))
            
            -- Check if token available
            if tokens >= 1 then
                tokens = tokens - 1
                redis.call('hmset', key, 'tokens', tokens, 'last_refill', now)
                redis.call('expire', key, 3600)
                return 1
            else
                return 0
            end";
        
        var result = await _redis.ScriptEvaluateAsync(
            script,
            new RedisKey[] { key },
            new RedisValue[] { now, maxTokens, refillRate }
        );
        
        return (int)result == 1;
    }
}

// Fixed Window Counter
public class FixedWindowRateLimiter
{
    private readonly IDatabase _redis;
    
    public FixedWindowRateLimiter(ConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }
    
    public async Task<bool> IsAllowedAsync(
        string clientId, 
        int limit = 100, 
        int windowSeconds = 60)
    {
        var window = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / windowSeconds;
        var key = $"ratelimit:{clientId}:{window}";
        
        var current = await _redis.StringIncrementAsync(key);
        
        if (current == 1)
        {
            await _redis.KeyExpireAsync(key, TimeSpan.FromSeconds(windowSeconds));
        }
        
        return current <= limit;
    }
}

// ASP.NET Core Rate Limiting Middleware
public class RedisRateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenBucketRateLimiter _rateLimiter;
    private readonly ILogger<RedisRateLimitingMiddleware> _logger;
    
    public RedisRateLimitingMiddleware(
        RequestDelegate next,
        TokenBucketRateLimiter rateLimiter,
        ILogger<RedisRateLimitingMiddleware> logger)
    {
        _next = next;
        _rateLimiter = rateLimiter;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var userId = context.User.Identity?.Name ?? 
                    context.Connection.RemoteIpAddress?.ToString() ?? 
                    "anonymous";
        
        var isAllowed = await _rateLimiter.AllowRequestAsync(userId, 100, 10);
        
        if (!isAllowed)
        {
            _logger.LogWarning("Rate limit exceeded for user {UserId}", userId);
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.Headers.Add("X-RateLimit-Limit", "100");
            context.Response.Headers.Add("X-RateLimit-Reset", 
                DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds().ToString());
            
            await context.Response.WriteAsync("Too many requests. Please try again later.");
            return;
        }
        
        await _next(context);
    }
}
```

## 4.5 PATTERN: Session Store

**Purpose:** Distributed session management

```csharp
public class RedisSessionStore
{
    private readonly IDatabase _redis;
    private readonly TimeSpan _defaultExpiry = TimeSpan.FromHours(1);
    
    public RedisSessionStore(ConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }
    
    public async Task<string> CreateSessionAsync(
        int userId, 
        string? ipAddress = null, 
        string? userAgent = null,
        TimeSpan? ttl = null)
    {
        var sessionId = Guid.NewGuid().ToString();
        var sessionKey = $"session:{sessionId}";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        var sessionData = new HashEntry[]
        {
            new("user_id", userId),
            new("created_at", now),
            new("last_activity", now),
            new("ip", ipAddress ?? string.Empty),
            new("user_agent", userAgent ?? string.Empty)
        };
        
        await _redis.HashSetAsync(sessionKey, sessionData);
        await _redis.KeyExpireAsync(sessionKey, ttl ?? _defaultExpiry);
        
        return sessionId;
    }
    
    public async Task<SessionData?> GetSessionAsync(string sessionId)
    {
        var sessionKey = $"session:{sessionId}";
        var sessionData = await _redis.HashGetAllAsync(sessionKey);
        
        if (sessionData.Length == 0)
            return null;
        
        // Sliding expiration - renew TTL on access
        await _redis.KeyExpireAsync(sessionKey, _defaultExpiry);
        
        return new SessionData
        {
            SessionId = sessionId,
            UserId = (int)sessionData.First(x => x.Name == "user_id").Value,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds((long)sessionData.First(x => x.Name == "created_at").Value),
            LastActivity = DateTimeOffset.FromUnixTimeSeconds((long)sessionData.First(x => x.Name == "last_activity").Value),
            IpAddress = sessionData.First(x => x.Name == "ip").Value,
            UserAgent = sessionData.First(x => x.Name == "user_agent").Value
        };
    }
    
    public async Task UpdateSessionActivityAsync(string sessionId)
    {
        var sessionKey = $"session:{sessionId}";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        await _redis.HashSetAsync(sessionKey, "last_activity", now);
        await _redis.KeyExpireAsync(sessionKey, _defaultExpiry);
    }
    
    public async Task InvalidateSessionAsync(string sessionId)
    {
        await _redis.KeyDeleteAsync($"session:{sessionId}");
    }
    
    public async Task<List<SessionData>> GetUserSessionsAsync(int userId)
    {
        // This requires a separate index - using Redis Set to track user sessions
        var userSessionsKey = $"user_sessions:{userId}";
        var sessionIds = await _redis.SetMembersAsync(userSessionsKey);
        
        var sessions = new List<SessionData>();
        foreach (var sessionId in sessionIds)
        {
            var session = await GetSessionAsync(sessionId!);
            if (session != null)
                sessions.Add(session);
        }
        
        return sessions;
    }
}

public class SessionData
{
    public string SessionId { get; set; }
    public int UserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastActivity { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
}

// ASP.NET Core custom session ID provider
public class RedisSessionIdManager
{
    private readonly RedisSessionStore _sessionStore;
    
    public RedisSessionIdManager(RedisSessionStore sessionStore)
    {
        _sessionStore = sessionStore;
    }
    
    public async Task<string> CreateSessionIdAsync(HttpContext context)
    {
        var userId = GetUserIdFromContext(context);
        var ipAddress = context.Connection.RemoteIpAddress?.ToString();
        var userAgent = context.Request.Headers["User-Agent"].ToString();
        
        return await _sessionStore.CreateSessionAsync(userId, ipAddress, userAgent);
    }
}
```

## 4.6 PATTERN: Pub/Sub

**Purpose:** Asynchronous communication between components

```csharp
// Event Base Classes
public abstract class IntegrationEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime CreationDate { get; set; } = DateTime.UtcNow;
    public string EventType => GetType().Name;
}

public class UserRegisteredEvent : IntegrationEvent
{
    public int UserId { get; set; }
    public string Email { get; set; }
    public string Name { get; set; }
}

// Publisher Service
public class RedisEventPublisher
{
    private readonly ISubscriber _subscriber;
    private readonly ILogger<RedisEventPublisher> _logger;
    
    public RedisEventPublisher(ConnectionMultiplexer redis, ILogger<RedisEventPublisher> logger)
    {
        _subscriber = redis.GetSubscriber();
        _logger = logger;
    }
    
    public async Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default)
        where TEvent : IntegrationEvent
    {
        var channel = $"events:{@event.EventType}";
        var message = JsonSerializer.Serialize(@event);
        
        _logger.LogInformation("Publishing event {EventType} to channel {Channel}", 
            @event.EventType, channel);
        
        await _subscriber.PublishAsync(channel, message);
    }
}

// Subscriber Base Class
public abstract class RedisEventSubscriber<TEvent> : IHostedService where TEvent : IntegrationEvent
{
    private readonly ISubscriber _subscriber;
    private readonly ILogger<RedisEventSubscriber<TEvent>> _logger;
    private readonly ChannelMessageQueue _queue;
    
    public RedisEventSubscriber(ConnectionMultiplexer redis, ILogger<RedisEventSubscriber<TEvent>> logger)
    {
        _subscriber = redis.GetSubscriber();
        _logger = logger;
        
        var channel = $"events:{typeof(TEvent).Name}";
        _queue = _subscriber.Subscribe(channel);
    }
    
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _queue.OnMessage(async message =>
        {
            try
            {
                var eventData = JsonSerializer.Deserialize<TEvent>(message.Message);
                await HandleEventAsync(eventData, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing event {EventType}", typeof(TEvent).Name);
            }
        });
        
        _logger.LogInformation("Started subscriber for {EventType}", typeof(TEvent).Name);
        return Task.CompletedTask;
    }
    
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _queue.UnsubscribeAsync();
        _logger.LogInformation("Stopped subscriber for {EventType}", typeof(TEvent).Name);
    }
    
    protected abstract Task HandleEventAsync(TEvent @event, CancellationToken cancellationToken);
}

// Concrete Subscriber Implementation
public class UserRegisteredEventHandler : RedisEventSubscriber<UserRegisteredEvent>
{
    private readonly IEmailService _emailService;
    private readonly ILogger<UserRegisteredEventHandler> _logger;
    
    public UserRegisteredEventHandler(
        ConnectionMultiplexer redis,
        IEmailService emailService,
        ILogger<UserRegisteredEventHandler> logger) : base(redis, logger)
    {
        _emailService = emailService;
        _logger = logger;
    }
    
    protected override async Task HandleEventAsync(UserRegisteredEvent @event, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Processing user registration for user {UserId}", @event.UserId);
        
        // Send welcome email
        await _emailService.SendWelcomeEmailAsync(@event.Email, @event.Name);
        
        // Update analytics
        // Update CRM
        // etc.
    }
}

// Dependency Injection Registration
public static class RedisPubSubExtensions
{
    public static IServiceCollection AddRedisEventing(this IServiceCollection services)
    {
        services.AddSingleton<RedisEventPublisher>();
        services.AddHostedService<UserRegisteredEventHandler>();
        
        return services;
    }
}

// Usage in Controller
[ApiController]
[Route("api/users")]
public class UsersController : ControllerBase
{
    private readonly RedisEventPublisher _eventPublisher;
    
    public UsersController(RedisEventPublisher eventPublisher)
    {
        _eventPublisher = eventPublisher;
    }
    
    [HttpPost]
    public async Task<IActionResult> RegisterUser([FromBody] RegisterUserRequest request)
    {
        // Register user in database
        var user = await _userService.RegisterUserAsync(request);
        
        // Publish event
        await _eventPublisher.PublishAsync(new UserRegisteredEvent
        {
            UserId = user.Id,
            Email = user.Email,
            Name = user.Name
        });
        
        return Ok(user);
    }
}
```

---

# MODULE 5: REDIS STREAMS - SPECIAL TOPIC

## 5.1 What are Redis Streams?

Redis Streams is an append-only log data structure, similar to Kafka, designed for:
- **Real-time event ingestion**
- **Asynchronous processing** with guarantees
- **Consumer groups** with message acknowledgment
- **Replay** of historical events

**Introduced in Redis 5.0**

## 5.2 Basic Stream Operations in C#

```csharp
public class RedisStreamService
{
    private readonly IDatabase _db;
    
    public RedisStreamService(ConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
    }
    
    // XADD - Add entry to stream
    public async Task<string> AddToStreamAsync(string streamKey, NameValueEntry[] fields)
    {
        // XADD sensor:temperature * temp 23.5 hum 45
        var
