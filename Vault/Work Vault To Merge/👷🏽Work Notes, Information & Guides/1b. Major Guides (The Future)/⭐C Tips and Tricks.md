

- Print sizeof() with %zu
- Print size_t with %zu
- Unsigned long is 8 bytes long on s21+. (Makes since sense it's x64 system)
	- Long is 8 bytes. unsigned Long is 8. Long Long is 8. (Go figure 🤷🏽)
- 


# Conversions

```
    // Convert filesize to a long to use later.
    // kstrtol(buffer, 10, &file_size_long);
    // printk(KERN_ERR "File Size Long: %lu", file_size_long);
```



# Pointers

```

// rw_data->write_pos is a struct that contains a loff_t * pointer

printk(KERN_ERR "Write Pos Experiment %llu: ", rw_data->write_pos);
printk(KERN_ERR "Write Pos Experiment %llu: ", &rw_data->write_pos);

testvar = &rw_data->write_pos;

printk(KERN_ERR "TV %llu: ", testvar); // *
printk(KERN_ERR "TV Experiment %llu: ", &testvar); // **
printk(KERN_ERR "TV Experiment %llu: ", *testvar); // val
```



# Error 1:

"Implicit Declaration" error means you need to make sure a declaration of the function exists in the header file. For Android Studio app, use 'extern' keyword. For KT, don't use extern.


# Common Declarations and References

## fs.h

```
extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);

extern loff_t vfs_llseek(struct file *file, loff_t offset, int whence);
```

## kernel.h

```
int __must_check _kstrtoul(const char *s, unsigned int base, unsigned long *res);
```





