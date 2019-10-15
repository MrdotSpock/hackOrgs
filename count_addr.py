def count(src_to_dest):
    dict_of_names = dict()
    final_dict = dict()
    for key in src_to_dest:
        for addr in src_to_dest[key]:
            if addr in dict_of_names:
                dict_of_names[addr] += 1
            else:
                dict_of_names[addr] = 1
        for i in dict_of_names:
            if key in final_dict:
                x = (i, dict_of_names[i])
                final_dict[key].append(x)
            else:
                final_dict[key] = []
                x = (i, dict_of_names[i])
                final_dict[key].append(x)
        dict_of_names.clear()
