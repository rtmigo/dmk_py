#### Header

n | name       | size    | description
---|-----------|---------|------------------------------------------------------------
hdr| format_id  | 2 bytes | 'LS'
hdr| format_ver | uint8   | File format version. Always 1
hdr| item_ver   | uint64  | Increases each time the item is rewritten 
hdr| parts_len  | uint16  | The total number of parts (files) storing the content of the item 
hdr| part_idx   | uint16  | Zero-based part number contained in the current file




 