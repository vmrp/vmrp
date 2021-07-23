//  luser_number.h -- number type configuration for Lua core
#define USE_INT

#ifdef USE_DOUBLE
#define MRP_NUMBER		double
#define MRP_NUMBER_SCAN		"%lf"
#define MRP_NUMBER_FMT		"%.14g"
#endif

#ifdef USE_FLOAT
#define MRP_NUMBER		float
#define MRP_NUMBER_SCAN		"%f"
#define MRP_NUMBER_FMT		"%.5g"
#endif

#ifdef USE_LONG
#define MRP_NUMBER		long
#define MRP_NUMBER_SCAN		"%ld"
#define MRP_NUMBER_FMT		"%ld"
#define mrp_str2number(s,p)     STRTOL((s), (p), 10)
#endif

#ifdef USE_INT
#define MRP_NUMBER		int
#define MRP_NUMBER_SCAN		"%d"
#define MRP_NUMBER_FMT		"%d"
#define mrp_str2number(s,p)     ((int) STRTOL((s), (p), 10))  
//ouli brew need change
#define mrp_number2str(s,n)     SPRINTF((s), MRP_NUMBER_FMT, (n))
//ouli brew
#endif

#ifdef USE_FASTROUND
#define mrp_number2int(i,d)	__asm__("fldl %1\nfistpl %0":"=m"(i):"m"(d))
#endif

