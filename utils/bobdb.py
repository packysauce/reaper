
# Bob uses individual numbers and ranges for values in his tables.
# This is a utility to break those apart into a tuple of ranges
# Useful for putting together relationships between Django DB models
#  when Bob has used this data storage technique

def desparse(sparse_string):
    result = []
    for item in sparse_string.split(','):
        parts = item.split('-')
        if len(parts) == 1:
            result.append(int(parts[0]))
        elif len(parts) == 2:
            [result.append(i) for i in range(int(parts[0]),int(parts[1])+1)]

    return sorted(result)
