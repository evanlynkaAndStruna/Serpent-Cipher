package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Border;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;


public class Main extends Application {
    private TextField textInput = new TextField();
    private TextField keyInput = new TextField();
    private Label result = new Label();
    private Label message = new Label();
    private Label key = new Label();
    private TextField resultInput = new TextField();
    private Button encryptBtn = new Button();
    private Button decryptBtn = new Button();
    private Button generateKey = new Button();
    private Label ivLabel = new Label();
    private TextField ivInput = new TextField();

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        primaryStage.setTitle("Serpent Cipher");

        Image image = new Image("file:serpent.png");
        ImageView imageView = new ImageView();
        imageView.setImage(image);
        imageView.setFitWidth(100);
        imageView.setFitHeight(100);

        primaryStage.getIcons().add(image);

        encryptBtn.setPrefWidth(180);
        decryptBtn.setPrefWidth(180);
        encryptBtn.setPrefHeight(30);
        decryptBtn.setPrefHeight(30);

        encryptBtn.setText("Encrypt");
        decryptBtn.setText("Decrypt");

        generateKey.setText("Generate key");
        generateKey.setPrefWidth(100);
        generateKey.setOnAction(value -> keyInput.setText(Serpent.generateKey()));

        encryptBtn.setOnAction(value ->  {
            String msg = textInput.getText();
            String k = keyInput.getText();

            if (msg.length() == 0){
                textInput.setStyle("-fx-border-color: red ; -fx-border-width: 2px ;");
                textInput.setPromptText("Enter plain text");
            }else{
                textInput.setStyle("");
                textInput.setPromptText("");
            }

            if (k.length() == 0){
                keyInput.setStyle("-fx-border-color: red ; -fx-border-width: 2px ;");
                keyInput.setPromptText("Enter key");
            }else{
                keyInput.setStyle("");
                keyInput.setPromptText("");
            }

            if (msg.length() > 0 && k.length() > 0){
                String iv = ivInput.getText();
                if (iv.length() > 0){
                    resultInput.setText(Serpent.encrypt(msg, k, iv));
                }else {
                    resultInput.setText(Serpent.encrypt(msg, k, false));
                }
            }
        });

        decryptBtn.setOnAction(value ->  {
            String msg = resultInput.getText();
            String k = keyInput.getText();

            if (msg.length() == 0){
                resultInput.setStyle("-fx-border-color: red ; -fx-border-width: 2px ;");
                resultInput.setPromptText("Enter plain text");
            }else{
                resultInput.setStyle("");
                resultInput.setPromptText("");
            }

            if (k.length() == 0){
                keyInput.setStyle("-fx-border-color: red ; -fx-border-width: 2px ;");
                keyInput.setPromptText("Enter key");
            }else{
                keyInput.setStyle("");
                keyInput.setPromptText("");
            }

            if (msg.length() > 0 && k.length() > 0){
                String iv = ivInput.getText();
                if (iv.length() > 0){
                    textInput.setText(Serpent.decrypt(msg, k, iv));
                }else {
                    textInput.setText(Serpent.decrypt(msg, k, false));
                }
            }
        });

        result.setText("Cryptogram:");
        message.setText("Plain text:");
        ivLabel.setText("Initialization vector (optional):");
        key.setText("Key:");
        key.setStyle("-fx-font-weight: bold;");
        resultInput.setBorder(Border.EMPTY);

        VBox v1 = createHbox(result, resultInput);
        VBox v2 = createHbox(message, textInput);
        VBox v3 = createHbox(key, keyInput);
        VBox v4 = createHbox(ivLabel, ivInput);

        HBox hBox = new HBox(encryptBtn, decryptBtn);
        hBox.setSpacing(50);
        hBox.setAlignment(Pos.CENTER);

        VBox vbox1 = new VBox(imageView,v1,v2,v3,v4);
        vbox1.setAlignment(Pos.CENTER);
        vbox1.setSpacing(20);

        VBox vbox2 = new VBox(vbox1,hBox,generateKey);
        vbox2.setSpacing(40);
        vbox2.setPadding(new Insets(20,10,20,10));
        vbox2.setAlignment(Pos.CENTER);

        Scene scene = new Scene(vbox2, 450, 580);

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public VBox createHbox(Label l, TextField t){
        VBox vbox = new VBox(l, t);
        vbox.setAlignment(Pos.CENTER);
        vbox.setSpacing(5);
        return vbox;
    }

    public static void main(String[] args) {
        launch(args);
    }
}