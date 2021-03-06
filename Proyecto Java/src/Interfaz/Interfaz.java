package Interfaz;

import Modelo.FileShare;
import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Permite al usuario interacturar con la clase FileShare
 */
public class Interfaz extends javax.swing.JFrame {

    //Indica si las llaves que se usaran son las que se generan
    boolean defaultPath = true;

    //0 Si no se ha definido
    //1 Si es cifrado
    //2 Si es descifrado
    int mode = 0;

    //Objeto FileShare para acceder a métodos
    FileShare fileShare;

    /**
     *
     * @param fileShare objeto para acceder a métodos desde los componentes de la interfaz
     */
    public Interfaz(FileShare fileShare) {
        this.fileShare = fileShare;
        initComponents();

        /*
            Listener para escuchar cambios en el directorio de creación de llaves y actualizar directorio de archivo
            de llave, si se utilizan las llaves generadas.
         */
        keyPath.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                if (defaultPath) {
                    setDefaultPath();
                }
            }
        });
        panelArchivos.setVisible(false);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jFileChooser1 = new javax.swing.JFileChooser();
        panelModo = new javax.swing.JPanel();
        radioCifrado = new javax.swing.JRadioButton();
        radioDescifrado = new javax.swing.JRadioButton();
        tituloPanelModo = new javax.swing.JLabel();
        panelLlaves = new javax.swing.JPanel();
        tituloLlaves = new javax.swing.JLabel();
        keyPath = new javax.swing.JTextField();
        keyPathChooser = new javax.swing.JButton();
        keysDefault = new javax.swing.JCheckBox();
        createKeysButton = new javax.swing.JButton();
        tituloRegistro = new javax.swing.JLabel();
        panelArchivos = new javax.swing.JPanel();
        tituloArchivos = new javax.swing.JLabel();
        archivo = new javax.swing.JTextField();
        tituloArchivo = new javax.swing.JLabel();
        tituloLlave = new javax.swing.JLabel();
        llave = new javax.swing.JTextField();
        fileChooser = new javax.swing.JButton();
        keyChooser = new javax.swing.JButton();
        doRSA = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        registro = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setForeground(new java.awt.Color(204, 204, 204));

        panelModo.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        buttonGroup1.add(radioCifrado);
        radioCifrado.setText("Cifrado");
        radioCifrado.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                radioCifradoActionPerformed(evt);
            }
        });

        buttonGroup1.add(radioDescifrado);
        radioDescifrado.setText("Descifrado");
        radioDescifrado.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                radioDescifradoActionPerformed(evt);
            }
        });

        tituloPanelModo.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        tituloPanelModo.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        tituloPanelModo.setText("Seleccione el modo de la aplicación");

        javax.swing.GroupLayout panelModoLayout = new javax.swing.GroupLayout(panelModo);
        panelModo.setLayout(panelModoLayout);
        panelModoLayout.setHorizontalGroup(
            panelModoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tituloPanelModo, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(panelModoLayout.createSequentialGroup()
                .addGap(71, 71, 71)
                .addGroup(panelModoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(radioCifrado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(radioDescifrado, javax.swing.GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))
                .addGap(71, 71, 71))
        );
        panelModoLayout.setVerticalGroup(
            panelModoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelModoLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tituloPanelModo)
                .addGap(18, 18, 18)
                .addComponent(radioCifrado)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(radioDescifrado)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        panelLlaves.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        tituloLlaves.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        tituloLlaves.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        tituloLlaves.setText("Seleccione ubicación de generación de llaves");

        keyPath.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyPathActionPerformed(evt);
            }
        });

        keyPathChooser.setText("Examinar");
        keyPathChooser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyPathChooserActionPerformed(evt);
            }
        });

        keysDefault.setSelected(true);
        keysDefault.setText("Usar estas llaves para el cifrado/descifrado");
        keysDefault.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keysDefaultActionPerformed(evt);
            }
        });

        createKeysButton.setText("Generar Llaves");
        createKeysButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createKeysButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelLlavesLayout = new javax.swing.GroupLayout(panelLlaves);
        panelLlaves.setLayout(panelLlavesLayout);
        panelLlavesLayout.setHorizontalGroup(
            panelLlavesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelLlavesLayout.createSequentialGroup()
                .addComponent(tituloLlaves, javax.swing.GroupLayout.PREFERRED_SIZE, 262, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(panelLlavesLayout.createSequentialGroup()
                .addGroup(panelLlavesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(panelLlavesLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(panelLlavesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(keysDefault)
                            .addGroup(panelLlavesLayout.createSequentialGroup()
                                .addComponent(keyPath, javax.swing.GroupLayout.PREFERRED_SIZE, 216, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(keyPathChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(panelLlavesLayout.createSequentialGroup()
                        .addGap(78, 78, 78)
                        .addComponent(createKeysButton)))
                .addContainerGap(19, Short.MAX_VALUE))
        );
        panelLlavesLayout.setVerticalGroup(
            panelLlavesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelLlavesLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tituloLlaves)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelLlavesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(keyPath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyPathChooser))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(keysDefault)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(createKeysButton)
                .addGap(29, 29, 29))
        );

        tituloRegistro.setFont(new java.awt.Font("Segoe UI", 1, 11)); // NOI18N
        tituloRegistro.setText("Registro:");

        panelArchivos.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        tituloArchivos.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        tituloArchivos.setText("Seleccione el archivo a cifrar y la llave pública");

        archivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                archivoActionPerformed(evt);
            }
        });

        tituloArchivo.setText("Archivo a cifrar:");

        tituloLlave.setText("Llave pública:");

        llave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                llaveActionPerformed(evt);
            }
        });

        fileChooser.setText("Examinar");
        fileChooser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fileChooserActionPerformed(evt);
            }
        });

        keyChooser.setText("Examinar");
        keyChooser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyChooserActionPerformed(evt);
            }
        });

        doRSA.setText("Cifrar");
        doRSA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                doRSAActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelArchivosLayout = new javax.swing.GroupLayout(panelArchivos);
        panelArchivos.setLayout(panelArchivosLayout);
        panelArchivosLayout.setHorizontalGroup(
            panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelArchivosLayout.createSequentialGroup()
                .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(panelArchivosLayout.createSequentialGroup()
                        .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(panelArchivosLayout.createSequentialGroup()
                                .addGap(117, 117, 117)
                                .addComponent(tituloArchivos))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelArchivosLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(archivo, javax.swing.GroupLayout.DEFAULT_SIZE, 198, Short.MAX_VALUE)
                                    .addComponent(tituloArchivo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(fileChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 29, Short.MAX_VALUE)
                                .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(tituloLlave, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(llave, javax.swing.GroupLayout.DEFAULT_SIZE, 209, Short.MAX_VALUE))))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keyChooser, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(panelArchivosLayout.createSequentialGroup()
                        .addGap(191, 191, 191)
                        .addComponent(doRSA, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        panelArchivosLayout.setVerticalGroup(
            panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelArchivosLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tituloArchivos)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tituloArchivo)
                    .addComponent(tituloLlave))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(panelArchivosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(archivo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(llave, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(fileChooser)
                    .addComponent(keyChooser))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(doRSA)
                .addGap(6, 6, 6))
        );

        jScrollPane1.setViewportView(registro);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(panelModo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(panelLlaves, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addComponent(panelArchivos, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(tituloRegistro)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane1))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(panelLlaves, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(panelModo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(panelArchivos, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tituloRegistro)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 254, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void radioDescifradoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_radioDescifradoActionPerformed
        //Cambiar texto de interfaz según modo de operación
        tituloArchivos.setText("Seleccione el archivo a descrifrar y la llave privada");
        tituloLlave.setText("Llave privada:");
        tituloArchivo.setText("Archivo a descifrar:");
        doRSA.setText("Descifrar");
        panelArchivos.setVisible(true);
        mode = 2;
        setDefaultPath();
    }//GEN-LAST:event_radioDescifradoActionPerformed

    private void radioCifradoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_radioCifradoActionPerformed
        //Cambiat texto de interfaz según modo de operación
        tituloArchivos.setText("Seleccione el archivo a descrifrar y la llave pública");
        tituloLlave.setText("Llave pública:");
        tituloArchivo.setText("Archivo a cifrar:");
        doRSA.setText("Cifrar");
        panelArchivos.setVisible(true);
        mode = 1;
        setDefaultPath();
    }//GEN-LAST:event_radioCifradoActionPerformed

    private void keyPathChooserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keyPathChooserActionPerformed
        //Seleccionar directorio donde se almacenaran las llaves
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Seleccione la ubicación para almacenar las llaves");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            keyPath.setText(chooser.getSelectedFile().getAbsolutePath() + "\\");
        }
    }//GEN-LAST:event_keyPathChooserActionPerformed

    private void createKeysButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createKeysButtonActionPerformed
        //Crear las llaves
        //Si no se indica ningun directorio, se crean en el directorio del proyecto     
        try {
            if (keyPath.getText().equals("")) {
                fileShare.crearClaves("");
                registro.setText(registro.getText() + "Se han creado las llaves en: "
                        + System.getProperty("user.dir") + "\n");
            } else {
                fileShare.crearClaves(keyPath.getText() + "\\");
                registro.setText(registro.getText() + "Se han creado las llaves en: " + keyPath.getText() + "\n");
            }
        } catch (Exception e) {
            e.printStackTrace();
            registro.setText(registro.getText() + "Hubo un problema al generar las llaves.\n");
        }
    }//GEN-LAST:event_createKeysButtonActionPerformed

    private void keyChooserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keyChooserActionPerformed
        /*
            Escoger la llave pública/privada para realizar cifrado/descifrado
            (Esto solo en caso de que el usuario quiera usar otras llaves, lo cual se
            indica en el checkbox)            
         */
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Seleccione la " + tituloLlave.getText());
        chooser.addChoosableFileFilter(new FileNameExtensionFilter("*.pem", "pem"));
        chooser.setAcceptAllFileFilterUsed(false);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            llave.setText(chooser.getSelectedFile().getAbsolutePath());
        }

    }//GEN-LAST:event_keyChooserActionPerformed

    private void fileChooserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fileChooserActionPerformed
        //Seleccionar archivo a cifrar/descifrar
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Seleccione el archivo");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            archivo.setText(chooser.getSelectedFile().getAbsolutePath());
        }

    }//GEN-LAST:event_fileChooserActionPerformed

    private void llaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_llaveActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_llaveActionPerformed

    private void archivoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_archivoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_archivoActionPerformed

    private void keysDefaultActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keysDefaultActionPerformed
        /*
            Este checkbox indica si se usarán las mismas llaves generadas con el programa, para realizar
            la operación. En ese caso el path del archivo de la llave será el mismo indicado en el de la
            generación de la llave.
         */

        defaultPath = !defaultPath;
        setDefaultPath();
    }//GEN-LAST:event_keysDefaultActionPerformed

    private void keyPathActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keyPathActionPerformed

    }//GEN-LAST:event_keyPathActionPerformed

    private void doRSAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_doRSAActionPerformed

        //Indica si se puede cifrar/descifrar
        boolean canRsa = true;
        File key = null;
        File file = null;

        if (llave.getText().equals("") || archivo.getText().equals("")) {

            JOptionPane.showMessageDialog(this, "Debe seleccionar un archivo y una llave",
                    "No se puede realizar la operación", JOptionPane.ERROR_MESSAGE);

        } else {

            key = new File(llave.getText());
            file = new File(archivo.getText());

            //Revisar archivo para verificar que sea valido para la operacion
            try {
                FileInputStream inputStream = new FileInputStream(file);
                if (inputStream.available() > 117 && mode == 1) {
                    JOptionPane.showMessageDialog(this, "El tamaño del archivo es muy grande, debe ser menor a 117 Bytes",
                            "No se puede realizar la operación", JOptionPane.ERROR_MESSAGE);
                    canRsa = false;
                }
            } catch (Exception e) {
                registro.setText(registro.getText() + "Hubo un problema al obtener el archivo.\n");
            }

            //Revisar archivo de llave para verificar que sea valido para la operacion
            try {
                FileInputStream inputStream = new FileInputStream(key);
                byte[] keyBytes = new byte[inputStream.available()];
                inputStream.read(keyBytes);

                String privateString = new String(keyBytes, "UTF-8");
                if (mode == 1 && privateString.contains("PRIVATE")) {
                    JOptionPane.showMessageDialog(this, "Para cifrar se necesita una llave pública",
                            "No se puede realizar el cifrado", JOptionPane.ERROR_MESSAGE);
                    canRsa = false;
                }
                if (mode == 2 && privateString.contains("PUBLIC")) {
                    JOptionPane.showMessageDialog(this, "Para descifrar se necesita una llave privada",
                            "No se puede realizar el descifrado", JOptionPane.ERROR_MESSAGE);
                    canRsa = false;
                }
            } catch (Exception e) {
                registro.setText(registro.getText() + "Hubo un problema al obtener el archivo de la llave.\n");
            }

            //Realizar operacion de cifrado o descifrado segun corresponda
            if (canRsa) {

                try {

                    //Cifrado
                    if (mode == 1) {

                        fileShare.cifrarArchivo(archivo.getText(), llave.getText());
                        registro.setText(registro.getText() + "\nSe ha cifrado el archivo " + file.getName() + "\n");
                        Path filepath = Paths.get(archivo.getText());
                        registro.setText(registro.getText() + "El archivo se puede encontrar en " + 
                                filepath.getParent().toString() + "\n");

                    }

                    //Descifrado
                    if (mode == 2) {

                        fileShare.descifrarArchivo(archivo.getText(), llave.getText());
                        registro.setText(registro.getText() + "\nSe ha descifrado el archivo " + file.getName() + "\n");
                        Path keypath = Paths.get(llave.getText());
                        registro.setText(registro.getText() + "El archivo se puede encontrar en " + 
                                keypath.getParent().toString() + "\n");

                    }

                } catch (Exception e) {

                    e.printStackTrace();
                    registro.setText(registro.getText() + "No se ha podido realizar la operación");

                }

            }

        }
    }//GEN-LAST:event_doRSAActionPerformed

    //Esta funcion asigna el archivo de llave en caso de que se vayan a usar las llaves generadas para la operación
    private void setDefaultPath() {
        if (defaultPath == true) {
            keyChooser.setEnabled(false);
            llave.setEnabled(false);
            if (mode == 1) {
                llave.setText(keyPath.getText() + "public_key.pem");
            }
            if (mode == 2) {
                llave.setText(keyPath.getText() + "private_key.pem");
            }
        } else {
            keyChooser.setEnabled(true);
            llave.setEnabled(true);
            llave.setBackground(Color.WHITE);
            llave.setText("");
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField archivo;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton createKeysButton;
    private javax.swing.JButton doRSA;
    private javax.swing.JButton fileChooser;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton keyChooser;
    private javax.swing.JTextField keyPath;
    private javax.swing.JButton keyPathChooser;
    private javax.swing.JCheckBox keysDefault;
    private javax.swing.JTextField llave;
    private javax.swing.JPanel panelArchivos;
    private javax.swing.JPanel panelLlaves;
    private javax.swing.JPanel panelModo;
    private javax.swing.JRadioButton radioCifrado;
    private javax.swing.JRadioButton radioDescifrado;
    private javax.swing.JTextPane registro;
    private javax.swing.JLabel tituloArchivo;
    private javax.swing.JLabel tituloArchivos;
    private javax.swing.JLabel tituloLlave;
    private javax.swing.JLabel tituloLlaves;
    private javax.swing.JLabel tituloPanelModo;
    private javax.swing.JLabel tituloRegistro;
    // End of variables declaration//GEN-END:variables
}
