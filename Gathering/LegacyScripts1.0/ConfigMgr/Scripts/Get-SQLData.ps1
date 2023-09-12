#
# SQL Audit Script
#
#Modify next 3 variables as appropriate. For $SQLServer: use SERVER\INSTANCE to access SQL instances
param (
	[Parameter(Mandatory=$true,HelpMessage="Enter outputpath, path must exist")]
	$Path,
	
	[Parameter(Mandatory=$true,HelpMessage="Enter FQDN to SQL server, for named instance use ServerFQDN\InstanceName")]
	$SQLServer = "SQL01.corp.viamonstra.com",
	
	[Parameter(Mandatory=$True,HelpMessage="Enter name of ConfigMgr DB, default CM_<Sitecode>")]
	$SQLCMDBName = "CM_PS1"
)

# Change working directory path as appropriate
Set-Location $Path
$dir = $Path

# Default SQL Server initial DB connection
$SQLDBName = "Master"
 
# Create and Open new connection 
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "Server = $SQLServer; Database = $SQLDBName; Integrated Security = True"

# 01-Server Properties
$SqlQuery = "SELECT SERVERPROPERTY('MachineName') AS [MachineName], SERVERPROPERTY('ServerName') AS [ServerName],  
SERVERPROPERTY('InstanceName') AS [Instance], SERVERPROPERTY('IsClustered') AS [IsClustered], 
SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS [ComputerNamePhysicalNetBIOS], 
SERVERPROPERTY('Edition') AS [Edition], SERVERPROPERTY('ProductLevel') AS [ProductLevel], 
SERVERPROPERTY('ProductVersion') AS [ProductVersion], SERVERPROPERTY('ProcessID') AS [ProcessID],
SERVERPROPERTY('Collation') AS [Collation], SERVERPROPERTY('IsFullTextInstalled') AS [IsFullTextInstalled], 
SERVERPROPERTY('IsIntegratedSecurityOnly') AS [IsIntegratedSecurityOnly];"

# Instantiate new SQLCommand objext, using prior connection
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand

# Set properties for SQLCommand
$SqlCmd.CommandText = $SqlQuery
$SqlCmd.Connection = $SqlConnection

# Instantiate new SQL data adapter object
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
$SqlAdapter.SelectCommand = $SqlCmd
 
# Instantiate new SQL Data Set Object 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
Clear-Host

# Pipe data to CSV format 
$DataSet.Tables[0] | export-csv ($dir + "\01-Server Properties.csv") -notypeinformation

# 02-Windows Info
$SqlQuery = "SELECT windows_release, windows_service_pack_level, 
       windows_sku, os_language_version
FROM sys.dm_os_windows_info WITH (NOLOCK) OPTION (RECOMPILE);"

# Re-use existing connection
$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\02-Windows Info.csv") -notypeinformation

# 03-Version Info
$SqlQuery = "SELECT @@SERVERNAME AS [Server Name], @@VERSION AS [SQL Server and OS Version Info];"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\03-Version Info.csv") -notypeinformation

# 04-SQL Server Install Date
$SqlQuery = "SELECT @@SERVERNAME AS [Server Name], createdate AS [SQL Server Install Date] 
FROM sys.syslogins WITH (NOLOCK)
WHERE [sid] = 0x010100000000000512000000;" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\04-SQL Server Install Date.csv") �notypeinformation

# 05-Configuration Values
$SqlQuery = "SELECT name, value, value_in_use, [description] 
FROM sys.configurations WITH (NOLOCK)
ORDER BY name OPTION (RECOMPILE);" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\05-Configuration Values.csv") -notypeinformation


# 06-DB File Names and paths
$SqlQuery = "SELECT DB_NAME([database_id])AS [Database Name], 
       [file_id], name, physical_name, type_desc, state_desc, 
       CONVERT( bigint, size/128.0) AS [Total Size in MB]
FROM sys.master_files WITH (NOLOCK)
WHERE [database_id] > 4 
AND [database_id] <> 32767
OR [database_id] = 2
ORDER BY DB_NAME([database_id]) OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\06-DB File Names and paths.csv") -notypeinformation


# 07-DB Properties
$SqlQuery = "SELECT db.[name] AS [Database Name], 
suser_sname( owner_sid ) As [Database Owner],
db.recovery_model_desc AS [Recovery Model], 
db.log_reuse_wait_desc AS [Log Reuse Wait Description], 
ls.cntr_value AS [Log Size (KB)], lu.cntr_value AS [Log Used (KB)],
CAST(CAST(lu.cntr_value AS FLOAT) / CAST(ls.cntr_value AS FLOAT)AS DECIMAL(18,2)) * 100 AS [Log Used %], 
db.[compatibility_level] AS [DB Compatibility Level], 
db.page_verify_option_desc AS [Page Verify Option], db.is_auto_create_stats_on, db.is_auto_update_stats_on,
db.is_auto_update_stats_async_on, db.is_parameterization_forced, 
db.snapshot_isolation_state_desc, db.is_read_committed_snapshot_on,
db.is_auto_close_on, db.is_auto_shrink_on, db.is_cdc_enabled
FROM sys.databases AS db WITH (NOLOCK)
INNER JOIN sys.dm_os_performance_counters AS lu WITH (NOLOCK)
ON db.name = lu.instance_name
INNER JOIN sys.dm_os_performance_counters AS ls WITH (NOLOCK) 
ON db.name = ls.instance_name
WHERE lu.counter_name LIKE N'Log File(s) Used Size (KB)%' 
AND ls.counter_name LIKE N'Log File(s) Size (KB)%'
AND ls.cntr_value > 0 OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\07-DB Properties.csv") -notypeinformation


# 08-Server Hardware
$SqlQuery = "SELECT cpu_count AS [Logical CPU Count], hyperthread_ratio AS [Hyperthread Ratio],
cpu_count/hyperthread_ratio AS [Physical CPU Count], 
physical_memory_in_bytes/1048576 AS [Physical Memory (MB)], 
sqlserver_start_time --, affinity_type_desc -- (affinity_type_desc is only in 2008 R2)
FROM sys.dm_os_sys_info WITH (NOLOCK) OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0]  | export-csv ($dir + "\08-Server Hardware.csv") -notypeinformation


# 09-System Manufacturer
$SqlQuery = "EXEC xp_readerrorlog 0,1,'Manufacturer';" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\09-System Manufacturer.csv") -notypeinformation


# 10-Fixed Drive Freespace
$SqlQuery = "EXEC xp_fixeddrives;" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\10-Fixed Drive Freespace.csv") -notypeinformation

# 11-IO Util by DB
$SqlQuery = "WITH Aggregate_IO_Statistics
AS
(SELECT DB_NAME(database_id) AS [Database Name],
CAST(SUM(num_of_bytes_read + num_of_bytes_written)/1048576 AS DECIMAL(12, 2)) AS io_in_mb
FROM sys.dm_io_virtual_file_stats(NULL, NULL) AS [DM_IO_STATS]
GROUP BY database_id)
SELECT ROW_NUMBER() OVER(ORDER BY io_in_mb DESC) AS [I/O Rank], [Database Name], io_in_mb AS [Total I/O (MB)],
       CAST(io_in_mb/ SUM(io_in_mb) OVER() * 100.0 AS DECIMAL(5,2)) AS [I/O Percent]
FROM Aggregate_IO_Statistics
ORDER BY [I/O Rank] OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\11-IO Util by DB.csv") -notypeinformation

# 12-System Memory
$SqlQuery = "SELECT total_physical_memory_kb/1024 AS [Physical Memory (MB)], 
       available_physical_memory_kb/1024 AS [Available Memory (MB)], 
       total_page_file_kb/1024 AS [Total Page File (MB)], 
	   available_page_file_kb/1024 AS [Available Page File (MB)], 
	   system_cache_kb/1024 AS [System Cache (MB)],
       system_memory_state_desc AS [System Memory State]
FROM sys.dm_os_sys_memory WITH (NOLOCK) OPTION (RECOMPILE);" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\12-System Memory.csv") -notypeinformation

# 13-Process Memory
$SqlQuery = "SELECT physical_memory_in_use_kb/1024 AS [SQL Server Memory Usage (MB)],
       large_page_allocations_kb, locked_page_allocations_kb, page_fault_count, 
	   memory_utilization_percentage, available_commit_limit_kb, 
	   process_physical_memory_low, process_virtual_memory_low
FROM sys.dm_os_process_memory WITH (NOLOCK) OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\13-Process Memory.csv") -notypeinformation

# 14-SQL Log file freespace
$SqlQuery = "DBCC SQLPERF(LOGSPACE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\14-SQL Log file freespace.csv") -notypeinformation

# Part 2
# Change to CM database for remainder of queries
# Reconnect to previous SQL connection
$SqlConnection.ConnectionString = "Server = $SQLServer; Database = $SQLCMDBName; Integrated Security = True"

# 15-CM File Sizes
# DB Name needed here...
$SqlQuery = "SELECT f.name AS [File Name] , f.physical_name AS [Physical Name], 
CAST((f.size/128.0) AS decimal(15,2)) AS [Total Size in MB],
CAST(f.size/128.0 - CAST(FILEPROPERTY(f.name, 'SpaceUsed') AS int)/128.0 AS decimal(15,2)) 
AS [Available Space In MB], [file_id], fg.name AS [Filegroup Name]
FROM sys.database_files AS f WITH (NOLOCK) 
LEFT OUTER JOIN sys.data_spaces AS fg WITH (NOLOCK) 
ON f.data_space_id = fg.data_space_id OPTION (RECOMPILE);"

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\15-CM File Sizes.csv") -notypeinformation

# 16-CM DB Statistics
$SqlQuery = "SELECT DISTINCT
	 OBJECT_NAME(s.[object_id]) AS TableName,
	 c.name AS ColumnName,
	 s.name AS StatName,
	 s.auto_created,
	 s.user_created,
	 s.no_recompute,
	 s.[object_id],
	 s.stats_id,
	 sc.stats_column_id,
	 sc.column_id,
	 STATS_DATE(s.[object_id], s.stats_id) AS LastUpdated
 FROM sys.stats s JOIN sys.stats_columns sc ON sc.[object_id] = s.[object_id] AND sc.stats_id = s.stats_id
	 JOIN sys.columns c ON c.[object_id] = sc.[object_id] AND c.column_id = sc.column_id
	 JOIN sys.partitions par ON par.[object_id] = s.[object_id]
	 JOIN sys.objects obj ON par.[object_id] = obj.[object_id]
 WHERE OBJECTPROPERTY(s.OBJECT_ID,'IsUserTable') = 1
	AND (s.auto_created = 1 OR s.user_created = 1);"  
	
$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\16-CM DB Statistics.csv") -notypeinformation

# 17-CM Index Frag
# This one may be a long running query, it is important to determine if the indeses are fragmented.
# Needed to extend query timeout parameter for this one to run!
# invoke-sqlcmd -QueryTimeout 65535 -database $DBName -query 
$SqlQuery = "SELECT DB_NAME(database_id) AS [Database Name], OBJECT_NAME(ps.OBJECT_ID) AS [Object Name], 
i.name AS [Index Name], ps.index_id, index_type_desc,
CONVERT(decimal,  avg_fragmentation_in_percent) AS PctFragmented, fragment_count, page_count
FROM sys.dm_db_index_physical_stats(DB_ID(),NULL, NULL, NULL ,N'LIMITED') AS ps 
INNER JOIN sys.indexes AS i WITH (NOLOCK)
ON ps.[object_id] = i.[object_id] 
AND ps.index_id = i.index_id
WHERE database_id = DB_ID()
AND page_count > 1500
ORDER BY avg_fragmentation_in_percent DESC OPTION (RECOMPILE);" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\17-CM Index Frag.csv") -notypeinformation

# 18 - VLF Information
# Virtual Log File - numbers below 50 are generally good. Large numbers of VLF can affect write performance, and startup times
$SqlQuery = "DBCC LOGINFO;" 

$SqlCmd.CommandText = $SqlQuery
$SqlAdapter.SelectCommand = $SqlCmd
 
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet)
 
Clear-Host
 
$DataSet.Tables[0] | export-csv ($dir + "\18-CM VLF Info.csv") -notypeinformation


$SqlConnection.Close()

Write-Warning "Run the complie script on a machine that has Office installed!"
