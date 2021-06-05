from flask import Flask, render_template, flash, request
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField

import pickle
import numpy as np
# App config.
DEBUG = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'

model=pickle.load(open('model.pkl','rb'))

'''
'duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land',
       'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
       'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations',
       'num_shells', 'num_access_files', 'is_guest_login', 'count',
       'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
       'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
       'dst_host_srv_count', 'dst_host_diff_srv_rate',
       'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate']
'''


@app.route('/predict', methods=['post', 'get'])
def predict():
    prediction = ''
    if request.method == 'POST':
        print(request.form)
        test=[]
        for key,item in request.form.items():
            print(key,item)
            test.append(item)
        test2=[[0.00000000e+00 ,5.00000000e-01, 0.00000000e+00, 2.61041764e-07,
                1.05713002e-03, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                0.00000000e+00 ,0.00000000e+00 ,1.00000000e+00, 0.00000000e+00,
                0.00000000e+00 ,0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                0.00000000e+00 ,0.00000000e+00, 1.56555773e-02, 1.56555773e-02,
                    0.00000000e+00, 0.00000000e+00 ,1.00000000e+00 ,0.00000000e+00,
                                0.00000000e+00, 3.52941176e-02, 3.52941176e-02, 0.00000000e+00,
                    1.10000000e-01, 0.00000000e+00]]

  
        prediction=model.predict(test2)
        print(prediction,'predection')        
    return render_template('index.html', message=prediction)


if __name__ == "__main__":
    app.run()

